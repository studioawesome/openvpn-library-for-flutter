/*
 * Copyright (c) 2012-2016 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.core;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import de.blinkt.openvpn.VpnProfile;

public class ProfileManager {
    private static final String PREFS_NAME = "VPNList";
    private static final String LAST_CONNECTED_PROFILE = "lastConnectedProfile";
    private static final String TEMPORARY_PROFILE_FILENAME = "temporary-vpn-profile";
    private static ProfileManager instance;
    private static VpnProfile tmpprofile = null;
    private HashMap<String, VpnProfile> profiles = new HashMap<>();

    private ProfileManager() {
    }

    private static VpnProfile get(String key) {
        if (tmpprofile != null && tmpprofile.getUUIDString().equals(key))
            return tmpprofile;

        if (instance == null)
            return null;
        return instance.profiles.get(key);
    }

    private synchronized static void checkInstance(Context context) {
        if (instance == null) {
            instance = new ProfileManager();
            instance.loadVPNList(context);
        }
    }

    public static void setConntectedVpnProfileDisconnected(Context c) {
        SharedPreferences prefs = Preferences.getDefaultSharedPreferences(c);
        Editor prefsedit = prefs.edit();
        prefsedit.putString(LAST_CONNECTED_PROFILE, null);
        prefsedit.apply();
    }

    /**
     * Sets the profile that is connected (to connect if the service restarts)
     */
    public static void setConnectedVpnProfile(Context c, VpnProfile connectedProfile) {
        SharedPreferences prefs = Preferences.getDefaultSharedPreferences(c);
        Editor prefsedit = prefs.edit();

        prefsedit.putString(LAST_CONNECTED_PROFILE, connectedProfile.getUUIDString());
        prefsedit.apply();
    }

    /**
     * Returns the profile that was last connected (to connect if the service restarts)
     */
    public static VpnProfile getLastConnectedProfile(Context c) {
        SharedPreferences prefs = Preferences.getDefaultSharedPreferences(c);

        String lastConnectedProfile = prefs.getString(LAST_CONNECTED_PROFILE, null);
        if (lastConnectedProfile != null)
            return get(c, lastConnectedProfile);
        else
            return null;
    }

    public static void setTemporaryProfile(Context c, VpnProfile tmp) {
        tmp.mTemporaryProfile = true;
        ProfileManager.tmpprofile = tmp;
        saveProfile(c, tmp);
    }

    public static void saveProfile(Context context, VpnProfile profile) {
        ObjectOutputStream vpnFile;

        String filename = profile.getUUID().toString();

        if (profile.mTemporaryProfile)
            filename = TEMPORARY_PROFILE_FILENAME;

        String deleteIfExists;
        try {
            FileOutputStream vpnFileOut = context.openFileOutput(filename + ".vp", Activity.MODE_PRIVATE);
            deleteIfExists = filename + ".cp";

            vpnFile = new ObjectOutputStream(vpnFileOut);

            vpnFile.writeObject(profile);
            vpnFile.flush();
            vpnFile.close();

            File delete = context.getFileStreamPath(deleteIfExists);
            if (delete.exists())
            {
                //noinspection ResultOfMethodCallIgnored
                delete.delete();
            }


        } catch (IOException e) {
            VpnStatus.logException("saving VPN profile", e);
            throw new RuntimeException(e);
        }
    }

    public static VpnProfile get(Context context, String profileUUID) {
        checkInstance(context);
        return get(profileUUID);
    }

    public static VpnProfile getAlwaysOnVPN(Context context) {
        checkInstance(context);
        SharedPreferences prefs = Preferences.getDefaultSharedPreferences(context);

        String uuid = prefs.getString("alwaysOnVpn", null);
        return get(uuid);
    }

    public Collection<VpnProfile> getProfiles() {
        return profiles.values();
    }

    private synchronized void loadVPNList(Context context) {
        profiles = new HashMap<>();
        SharedPreferences listpref = Preferences.getSharedPreferencesMulti(PREFS_NAME, context);
        Set<String> vlist = listpref.getStringSet("vpnlist", null);
        if (vlist == null) {
            vlist = new HashSet<>();
        }
        // Always try to load the temporary profile
        vlist.add(TEMPORARY_PROFILE_FILENAME);

        for (String vpnentry : vlist) {
            loadVpnEntry(context, vpnentry);
        }
    }

    private synchronized void loadVpnEntry(Context context, String vpnentry) {
        ObjectInputStream vpnfile = null;
        try {
            FileInputStream vpInput = context.openFileInput(vpnentry + ".vp");
            vpnfile = new ObjectInputStream(vpInput);
            VpnProfile vp = ((VpnProfile) vpnfile.readObject());

            // Sanity check
            if (vp == null || vp.mName == null || vp.getUUID() == null)
                return;

            vp.upgradeProfile();
            if (vpnentry.equals(TEMPORARY_PROFILE_FILENAME)) {
                tmpprofile = vp;
            } else {
                profiles.put(vp.getUUID().toString(), vp);
            }
        } catch (IOException | ClassNotFoundException e) {
            if (!vpnentry.equals(TEMPORARY_PROFILE_FILENAME))
                VpnStatus.logException("Loading VPN List", e);
        } finally {
            if (vpnfile != null) {
                try {
                    vpnfile.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
