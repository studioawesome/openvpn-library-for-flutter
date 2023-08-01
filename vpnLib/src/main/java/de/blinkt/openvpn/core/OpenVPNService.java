/*
 * Copyright (c) 2012-2016 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.core;

import static de.blinkt.openvpn.core.ConnectionStatus.LEVEL_CONNECTED;
import static de.blinkt.openvpn.core.ConnectionStatus.LEVEL_WAITING_FOR_USER_INPUT;
import static de.blinkt.openvpn.core.NetworkSpace.IpAddress;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.UiModeManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ShortcutManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.net.ConnectivityManager;
import android.net.ProxyInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Handler.Callback;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.system.OsConstants;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Vector;

import de.blinkt.openvpn.R;
import de.blinkt.openvpn.VpnProfile;
import de.blinkt.openvpn.core.VpnStatus.ByteCountListener;
import de.blinkt.openvpn.core.VpnStatus.StateListener;

public class OpenVPNService extends VpnService implements StateListener, Callback, ByteCountListener, IOpenVPNServiceInternal {
    public static final String START_SERVICE = "de.blinkt.openvpn.START_SERVICE";
    public static final String START_SERVICE_STICKY = "de.blinkt.openvpn.START_SERVICE_STICKY";
    public static final String NOTIFICATION_CHANNEL_BG_ID = "openvpn_bg";
    public static final String NOTIFICATION_CHANNEL_NEWSTATUS_ID = "openvpn_newstat";

    public static final String VPNSERVICE_TUN = "vpnservice-tun";
    private static final String TAG = "OpenVPNService";
    private static final int PRIORITY_MIN = -2;
    private static final int PRIORITY_DEFAULT = 0;
    private final Vector<String> mDnslist = new Vector<>();
    private final NetworkSpace mRoutes = new NetworkSpace();
    private final NetworkSpace mRoutesv6 = new NetworkSpace();
    private final Object mProcessLock = new Object();
    private Thread mProcessThread = null;
    private VpnProfile mProfile;
    private String mDomain = null;
    private CIDRIP mLocalIP = null;
    private int mMtu;
    private String mLocalIPv6 = null;
    private DeviceStateReceiver mDeviceStateReceiver;
    private boolean mDisplayBytecount = false;
    private boolean mStarting = false;
    private long mConnecttime;
    private OpenVPNManagement mManagement;
    private final IBinder mBinder = new IOpenVPNServiceInternal.Stub() {

        @Override
        public boolean protect(int fd) throws RemoteException {
            return OpenVPNService.this.protect(fd);
        }

        @Override
        public void userPause(boolean shouldbePaused) throws RemoteException {
            OpenVPNService.this.userPause(shouldbePaused);
        }

        @Override
        public boolean stopVPN(boolean replaceConnection) throws RemoteException {
            return OpenVPNService.this.stopVPN(replaceConnection);
        }

        @Override
        public void challengeResponse(String repsonse) throws RemoteException {
            OpenVPNService.this.challengeResponse(repsonse);
        }


    };
    private Handler guiHandler;
    private ProxyInfo mProxyInfo;
    private HandlerThread mCommandHandlerThread;
    private Handler mCommandHandler;

    // From: http://stackoverflow.com/questions/3758606/how-to-convert-byte-size-into-human-readable-format-in-java
    public static String humanReadableByteCount(long bytes, boolean speed, Resources res) {
        if (speed)
            bytes = bytes * 8;
        int unit = speed ? 1000 : 1024;


        int exp = Math.max(0, Math.min((int) (Math.log(bytes) / Math.log(unit)), 3));

        float bytesUnit = (float) (bytes / Math.pow(unit, exp));

        if (speed)
            switch (exp) {
                case 0:
                    return res.getString(R.string.bits_per_second, bytesUnit);
                case 1:
                    return res.getString(R.string.kbits_per_second, bytesUnit);
                case 2:
                    return res.getString(R.string.mbits_per_second, bytesUnit);
                default:
                    return res.getString(R.string.gbits_per_second, bytesUnit);
            }
        else
            switch (exp) {
                case 0:
                    return res.getString(R.string.volume_byte, bytesUnit);
                case 1:
                    return res.getString(R.string.volume_kbyte, bytesUnit);
                case 2:
                    return res.getString(R.string.volume_mbyte, bytesUnit);
                default:
                    return res.getString(R.string.volume_gbyte, bytesUnit);

            }
    }

    @Override
    public void challengeResponse(String response) throws RemoteException {
        if (mManagement != null) {
            String b64response = Base64.encodeToString(response.getBytes(StandardCharsets.UTF_8), Base64.DEFAULT);
            mManagement.sendCRResponse(b64response);
        }
    }


    @Override
    public IBinder onBind(Intent intent) {
        String action = intent.getAction();
        if (action != null && action.equals(START_SERVICE))
            return mBinder;
        else
            return super.onBind(intent);
    }

    @Override
    public void onRevoke() {
        Log.i(TAG, "onRevoke called");
        VpnStatus.logError(R.string.permission_revoked);
        mManagement.stopVPN(false);
        endVpnService();
    }

    // Similar to revoke but do not try to stop process
    public void openvpnStopped() {
        endVpnService();
    }

    private boolean isAlwaysActiveEnabled()
    {
        SharedPreferences prefs = Preferences.getDefaultSharedPreferences(this);
        return prefs.getBoolean("restartvpnonboot", false);
    }

    boolean isVpnAlwaysOnEnabled() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return isAlwaysOn();
        }
        return false;
    }


    private void endVpnService() {
        Log.i(TAG, "endVpnService called");
        if (!isVpnAlwaysOnEnabled() && !isAlwaysActiveEnabled()) {
            /* if we should be an always on VPN, keep the timer running */
            keepVPNAlive.unscheduleKeepVPNAliveJobService(this);
        }
        synchronized (mProcessLock) {
            mProcessThread = null;
        }
        VpnStatus.removeByteCountListener(this);
        unregisterDeviceStateReceiver(mDeviceStateReceiver);
        mDeviceStateReceiver = null;
        ProfileManager.setConntectedVpnProfileDisconnected(this);
        if (!mStarting) {
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
            VpnStatus.removeStateListener(this);
        }
    }

    private void showNotification(final String msg, String tickerText, @NonNull String channel,
                                  long when, ConnectionStatus status, Intent intent) {
        Log.i(TAG, "showNotification called, msg = " + msg + ", channel = " + channel);
        NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        int icon = getIconByConnectionStatus(status);

        android.app.Notification.Builder nbuilder = new Notification.Builder(this);

        int priority;
        if (channel.equals(NOTIFICATION_CHANNEL_BG_ID))
            priority = PRIORITY_MIN;
        else
            priority = PRIORITY_DEFAULT;

        if (mProfile != null)
            nbuilder.setContentTitle(getString(R.string.notifcation_title, mProfile.mName));
        else
            nbuilder.setContentTitle(getString(R.string.notifcation_title_notconnect));

        nbuilder.setContentText(msg);
        nbuilder.setOnlyAlertOnce(true);
        nbuilder.setOngoing(true);

        nbuilder.setSmallIcon(icon);
        if (status == LEVEL_WAITING_FOR_USER_INPUT) {
            PendingIntent pIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE);
            nbuilder.setContentIntent(pIntent);
        } else {
            nbuilder.setContentIntent(getMainActivityPendingIntent());
        }

        if (when != 0)
            nbuilder.setWhen(when);


        // Try to set the priority available since API 16 (Jellybean)
        jbNotificationExtras(priority, nbuilder);
        lpNotificationExtras(nbuilder, Notification.CATEGORY_SERVICE);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            //noinspection NewApi
            nbuilder.setChannelId(channel);
            if (mProfile != null)
                //noinspection NewApi
                nbuilder.setShortcutId(mProfile.getUUIDString());

        }

        if (tickerText != null && !tickerText.equals(""))
            nbuilder.setTicker(tickerText);

        @SuppressWarnings("deprecation")
        Notification notification = nbuilder.getNotification();

        int notificationId = channel.hashCode();

        mNotificationManager.notify(notificationId, notification);

        startForeground(notificationId, notification);
    }

    private void lpNotificationExtras(Notification.Builder nbuilder, String category) {
        nbuilder.setCategory(category);
        nbuilder.setLocalOnly(true);
    }

    private int getIconByConnectionStatus(ConnectionStatus level) {
        switch (level) {
            case LEVEL_CONNECTED:
                return R.drawable.ic_vpn_connected;
            default:
                return R.drawable.ic_vpn_disconnected;
        }
    }

    private void jbNotificationExtras(int priority,
                                      android.app.Notification.Builder nbuilder) {
        try {
            if (priority != 0) {
                Method setpriority = nbuilder.getClass().getMethod("setPriority", int.class);
                setpriority.invoke(nbuilder, priority);

                Method setUsesChronometer = nbuilder.getClass().getMethod("setUsesChronometer", boolean.class);
                setUsesChronometer.invoke(nbuilder, true);

            }

            //ignore exception
        } catch (NoSuchMethodException | IllegalArgumentException |
                InvocationTargetException | IllegalAccessException e) {
            VpnStatus.logException(e);
        }

    }

    PendingIntent getMainActivityPendingIntent() {
        // Let the configure Button show the Log
        Intent intent = new Intent();
        ComponentName componentName = new ComponentName(this, getPackageName() + ".MainActivity");
        intent.setComponent(componentName);

        intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        PendingIntent startLW = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE);
        return startLW;
    }

    synchronized void registerDeviceStateReceiver(DeviceStateReceiver newDeviceStateReceiver) {
        // Registers BroadcastReceiver to track network connection changes.
        IntentFilter filter = new IntentFilter();
        filter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        filter.addAction(Intent.ACTION_SCREEN_OFF);
        filter.addAction(Intent.ACTION_SCREEN_ON);

        // Fetch initial network state
        newDeviceStateReceiver.networkStateChange(this);

        registerReceiver(newDeviceStateReceiver, filter);
        VpnStatus.addByteCountListener(newDeviceStateReceiver);
    }

    synchronized void unregisterDeviceStateReceiver(DeviceStateReceiver deviceStateReceiver) {
        if (mDeviceStateReceiver != null)
            try {
                VpnStatus.removeByteCountListener(deviceStateReceiver);
                this.unregisterReceiver(deviceStateReceiver);
            } catch (IllegalArgumentException iae) {
                // I don't know why  this happens:
                // java.lang.IllegalArgumentException: Receiver not registered: de.blinkt.openvpn.NetworkSateReceiver@41a61a10
                // Ignore for now ...
                iae.printStackTrace();
            }
    }

    public void userPause(boolean shouldBePaused) {
        if (mDeviceStateReceiver != null)
            mDeviceStateReceiver.userPause(shouldBePaused);
    }

    @Override
    public boolean stopVPN(boolean replaceConnection) throws RemoteException {
        if (getManagement() != null)
            return getManagement().stopVPN(replaceConnection);
        else
            return false;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "onStartCommand called");
        if (intent != null) {
            Log.i(TAG, "intent = " + intent.toString());
        } else {
            Log.i(TAG, "intent is null");
        }

        VpnStatus.addStateListener(this);
        VpnStatus.addByteCountListener(this);

        if (intent != null && START_SERVICE.equals(intent.getAction()))
            return START_NOT_STICKY;
        if (intent != null && START_SERVICE_STICKY.equals(intent.getAction())) {
            return START_REDELIVER_INTENT;
        }

        // Always show notification here to avoid problem with startForeground timeout
        VpnStatus.logInfo(R.string.building_configration);
        VpnStatus.updateStateString("VPN_GENERATE_CONFIG", "", R.string.building_configration, ConnectionStatus.LEVEL_START);
        showNotification(VpnStatus.getLastCleanLogMessage(this),
                VpnStatus.getLastCleanLogMessage(this), NOTIFICATION_CHANNEL_NEWSTATUS_ID, 0, ConnectionStatus.LEVEL_START, null);


        /* start the OpenVPN process itself in a background thread */
        mCommandHandler.post(() -> startOpenVPN(intent, startId));

        return START_STICKY;
    }

    @RequiresApi(Build.VERSION_CODES.N_MR1)
    private void updateShortCutUsage(VpnProfile profile) {
        if (profile == null)
            return;
        ShortcutManager shortcutManager = getSystemService(ShortcutManager.class);
        if (shortcutManager!=null) {
            /* This should never been null but I do not trust Android ROMs to do the right thing
             * anymore and neither seems Coverity */
            shortcutManager.reportShortcutUsed(profile.getUUIDString());
        }
    }

    private VpnProfile fetchVPNProfile(Intent intent)
    {
        Log.i(TAG, "fetchVPNProfile called");
        String startReason;
        if (intent != null && intent.hasExtra(getPackageName() + ".profileUUID")) {
            Log.i(TAG, "ProfileManager.get() called");
            String profileUUID = intent.getStringExtra(getPackageName() + ".profileUUID");
            startReason = intent.getStringExtra(getPackageName() + ".startReason");
            if (startReason == null)
                startReason = "(unknown)";
            // Try for 10s to get current version of the profile
            mProfile = ProfileManager.get(this, profileUUID);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N_MR1) {
                updateShortCutUsage(mProfile);
            }

        } else {
            Log.i(TAG, "ProfileManager.getLastConnectedProfile() called");
            /* The intent is null when we are set as always-on or the service has been restarted. */
            mProfile = ProfileManager.getLastConnectedProfile(this);
            startReason = "Using last connected profile (started with null intent, always-on or restart after crash)";
            VpnStatus.logInfo(R.string.service_restarted);

            /* Got no profile, just stop */
            if (mProfile == null) {
                startReason = "could not get last connected profile, using default (started with null intent, always-on or restart after crash)";

                Log.i(TAG, "Got no last connected profile on null intent. Assuming always on.");
                mProfile = ProfileManager.getAlwaysOnVPN(this);


                if (mProfile == null) {
                    return null;
                }
            }
            /* Do the asynchronous keychain certificate stuff */
            mProfile.checkForRestart(this);
        }
        String name = "(null)";
        if (mProfile != null)
            name = mProfile.getName();
        VpnStatus.logDebug(String.format("Fetched VPN profile (%s) triggered by %s", name, startReason));
        return mProfile;
    }

    private void startOpenVPN(Intent intent, int startId) {
        Log.i(TAG, "startOpenVPN called");
        VpnProfile vp = fetchVPNProfile(intent);
        if (vp == null) {
            Log.i(TAG, "profile is null, stopping self");
            stopSelf(startId);
            return;
        }

        ProfileManager.setConnectedVpnProfile(this, mProfile);
        VpnStatus.setConnectedVPNProfile(mProfile.getUUIDString());
        keepVPNAlive.scheduleKeepVPNAliveJobService(this, vp);

        // Set a flag that we are starting a new VPN
        mStarting = true;
        // Stop the previous session by interrupting the thread.

        stopOldOpenVPNProcess();
        // An old running VPN should now be exited
        mStarting = false;

        OpenVPNManagement mOpenVPN3 = new OpenVPNThreadv3(this, mProfile);
        Runnable processThread = (Runnable) mOpenVPN3;
        mManagement = mOpenVPN3;

        synchronized (mProcessLock) {
            mProcessThread = new Thread(processThread, "OpenVPNProcessThread");
            mProcessThread.start();
        }

        final DeviceStateReceiver oldDeviceStateReceiver = mDeviceStateReceiver;
        final DeviceStateReceiver newDeviceStateReceiver = new DeviceStateReceiver(mManagement);

        guiHandler.post(() -> {
            if (oldDeviceStateReceiver != null)
                unregisterDeviceStateReceiver(oldDeviceStateReceiver);

            registerDeviceStateReceiver(newDeviceStateReceiver);
            mDeviceStateReceiver = newDeviceStateReceiver;
        });
    }

    private void stopOldOpenVPNProcess() {
        Log.i(TAG, "stopOldOpenVPNProcess called");
        if (mManagement != null) {
            if (mManagement.stopVPN(true)) {
                // an old was asked to exit, wait 1s
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    //ignore
                }
            }
        }

        forceStopOpenVpnProcess();
    }

    public void forceStopOpenVpnProcess() {
        Log.i(TAG, "forceStopOpenVpnProcess called");
        synchronized (mProcessLock) {
            if (mProcessThread != null) {
                mProcessThread.interrupt();
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    //ignore
                }
            }
        }
    }


    @Override
    public IBinder asBinder() {
        return mBinder;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "onCreate called");
        guiHandler = new Handler(getMainLooper());
        mCommandHandlerThread = new HandlerThread("OpenVPNServiceCommandThread");
        mCommandHandlerThread.start();
        mCommandHandler = new Handler(mCommandHandlerThread.getLooper());
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "onDestroy called");
        synchronized (mProcessLock) {
            if (mProcessThread != null) {
                mManagement.stopVPN(true);
            }
        }

        if (mDeviceStateReceiver != null) {
            unregisterDeviceStateReceiver(mDeviceStateReceiver);
            mDeviceStateReceiver = null;
        }
        // Just in case unregister for state
        VpnStatus.removeStateListener(this);
        VpnStatus.flushLog();
    }

    public ParcelFileDescriptor openTun() {
        Log.i(TAG, "openTun called");

        //Debug.startMethodTracing(getExternalFilesDir(null).toString() + "/opentun.trace", 40* 1024 * 1024);

        Builder builder = new Builder();

        VpnStatus.logInfo(R.string.last_openvpn_tun_config);

        if (mProfile == null)
        {
            VpnStatus.logError("OpenVPN tries to open a VPN descriptor with mProfile==null, please report this bug with log!");
            return null;
        }

        boolean allowUnsetAF = !mProfile.mBlockUnusedAddressFamilies;
        if (allowUnsetAF) {
            allowAllAFFamilies(builder);
        }

        if (mLocalIP == null && mLocalIPv6 == null) {
            VpnStatus.logError(getString(R.string.opentun_no_ipaddr));
            return null;
        }

        if (mLocalIP != null) {
            try {
                builder.addAddress(mLocalIP.mIp, mLocalIP.len);
            } catch (IllegalArgumentException iae) {
                VpnStatus.logError(R.string.dns_add_error, mLocalIP, iae.getLocalizedMessage());
                return null;
            }
        }

        if (mLocalIPv6 != null) {
            String[] ipv6parts = mLocalIPv6.split("/");
            try {
                builder.addAddress(ipv6parts[0], Integer.parseInt(ipv6parts[1]));
            } catch (IllegalArgumentException iae) {
                VpnStatus.logError(R.string.ip_add_error, mLocalIPv6, iae.getLocalizedMessage());
                return null;
            }

        }


        for (String dns : mDnslist) {
            try {
                builder.addDnsServer(dns);
            } catch (IllegalArgumentException iae) {
                VpnStatus.logError(R.string.dns_add_error, dns, iae.getLocalizedMessage());
            }
        }

        builder.setMtu(mMtu);

        Collection<IpAddress> positiveIPv4Routes = mRoutes.getPositiveIPList();
        Collection<IpAddress> positiveIPv6Routes = mRoutesv6.getPositiveIPList();

        if ("samsung".equals(Build.BRAND) && mDnslist.size() >= 1) {
            // Check if the first DNS Server is in the VPN range
            try {
                IpAddress dnsServer = new IpAddress(new CIDRIP(mDnslist.get(0), 32), true);
                boolean dnsIncluded = false;
                for (IpAddress net : positiveIPv4Routes) {
                    if (net.containsNet(dnsServer)) {
                        dnsIncluded = true;
                    }
                }
                if (!dnsIncluded) {
                    String samsungwarning = String.format("Warning Samsung Android 5.0+ devices ignore DNS servers outside the VPN range. To enable DNS resolution a route to your DNS Server (%s) has been added.", mDnslist.get(0));
                    VpnStatus.logWarning(samsungwarning);
                    positiveIPv4Routes.add(dnsServer);
                }
            } catch (Exception e) {
                // If it looks like IPv6 ignore error
                if (!mDnslist.get(0).contains(":"))
                    VpnStatus.logError("Error parsing DNS Server IP: " + mDnslist.get(0));
            }
        }


        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            installRoutesExcluded(builder, mRoutes);
            installRoutesExcluded(builder, mRoutesv6);
        } else {
            installRoutesPostiveOnly(builder, positiveIPv4Routes, positiveIPv6Routes);
        }


        if (mDomain != null)
            builder.addSearchDomain(mDomain);

        String ipv4info;
        String ipv6info;
        if (allowUnsetAF) {
            ipv4info = "(not set, allowed)";
            ipv6info = "(not set, allowed)";
        } else {
            ipv4info = "(not set)";
            ipv6info = "(not set)";
        }

        int ipv4len;
        if (mLocalIP != null) {
            ipv4len = mLocalIP.len;
            ipv4info = mLocalIP.mIp;
        } else {
            ipv4len = -1;
        }

        if (mLocalIPv6 != null) {
            ipv6info = mLocalIPv6;
        }

        if ((!mRoutes.getNetworks(false).isEmpty() || !mRoutesv6.getNetworks(false).isEmpty()) && isLockdownEnabledCompat()) {
            VpnStatus.logInfo("VPN lockdown enabled (do not allow apps to bypass VPN) enabled. Route exclusion will not allow apps to bypass VPN (e.g. bypass VPN for local networks)");
        }

        VpnStatus.logInfo(R.string.local_ip_info, ipv4info, ipv4len, ipv6info, mMtu);
        VpnStatus.logInfo(R.string.dns_server_info, TextUtils.join(", ", mDnslist), mDomain);
        VpnStatus.logInfo(R.string.routes_info_incl, TextUtils.join(", ", mRoutes.getNetworks(true)), TextUtils.join(", ", mRoutesv6.getNetworks(true)));
        VpnStatus.logInfo(R.string.routes_info_excl, TextUtils.join(", ", mRoutes.getNetworks(false)), TextUtils.join(", ", mRoutesv6.getNetworks(false)));
        if (mProxyInfo != null) {
            VpnStatus.logInfo(R.string.proxy_info, mProxyInfo.getHost(), mProxyInfo.getPort());
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            /* On Tiramisu we install the routes exactly like promised */
            VpnStatus.logDebug(R.string.routes_debug, TextUtils.join(", ", positiveIPv4Routes), TextUtils.join(", ", positiveIPv6Routes));
        }
        //VpnStatus.logInfo(String.format("Always active %s", isAlwaysOn() ? "on" : "off"));

        setAllowedVpnPackages(builder);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            // VPN always uses the default network
            builder.setUnderlyingNetworks(null);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Setting this false, will cause the VPN to inherit the underlying network metered
            // value
            builder.setMetered(false);
        }

        String session = mProfile.mName;
        if (mLocalIP != null && mLocalIPv6 != null)
            session = getString(R.string.session_ipv6string, session, mLocalIP, mLocalIPv6);
        else if (mLocalIP != null)
            session = getString(R.string.session_ipv4string, session, mLocalIP);
        else
            session = getString(R.string.session_ipv4string, session, mLocalIPv6);

        builder.setSession(session);

        // No DNS Server, log a warning
        if (mDnslist.size() == 0)
            VpnStatus.logInfo(R.string.warn_no_dns);

        setHttpProxy(builder);

        // Reset information
        mDnslist.clear();
        mRoutes.clear();
        mRoutesv6.clear();
        mLocalIP = null;
        mLocalIPv6 = null;
        mDomain = null;
        mProxyInfo = null;

        builder.setConfigureIntent(getMainActivityPendingIntent());

        try {
            //Debug.stopMethodTracing();
            ParcelFileDescriptor tun = builder.establish();
            if (tun == null)
                throw new NullPointerException("Android establish() method returned null (Really broken network configuration?)");
            return tun;
        } catch (Exception e) {
            VpnStatus.logError(R.string.tun_open_error);
            VpnStatus.logError(getString(R.string.error) + e.getLocalizedMessage());
            return null;
        }

    }

    private void installRoutesExcluded(Builder builder, NetworkSpace routes)
    {
        for(IpAddress ipIncl: routes.getNetworks(true))
        {
            try {
                builder.addRoute(ipIncl.getPrefix());
            } catch (UnknownHostException|IllegalArgumentException ia) {
                VpnStatus.logError(getString(R.string.route_rejected) + ipIncl + " " + ia.getLocalizedMessage());
            }
        }
        for(IpAddress ipExcl: routes.getNetworks(false))
        {
            try {
                builder.excludeRoute(ipExcl.getPrefix());
            } catch (UnknownHostException|IllegalArgumentException ia) {
                VpnStatus.logError(getString(R.string.route_rejected) + ipExcl + " " + ia.getLocalizedMessage());
            }
        }
    }

    private void installRoutesPostiveOnly(Builder builder, Collection<IpAddress> positiveIPv4Routes, Collection<IpAddress> positiveIPv6Routes) {
        IpAddress multicastRange = new IpAddress(new CIDRIP("224.0.0.0", 3), true);

        for (IpAddress route : positiveIPv4Routes) {
            try {
                if (multicastRange.containsNet(route))
                    VpnStatus.logDebug(R.string.ignore_multicast_route, route.toString());
                else
                    builder.addRoute(route.getIPv4Address(), route.networkMask);
            } catch (IllegalArgumentException ia) {
                VpnStatus.logError(getString(R.string.route_rejected) + route + " " + ia.getLocalizedMessage());
            }
        }

        for (IpAddress route6 : positiveIPv6Routes) {
            try {
                builder.addRoute(route6.getIPv6Address(), route6.networkMask);
            } catch (IllegalArgumentException ia) {
                VpnStatus.logError(getString(R.string.route_rejected) + route6 + " " + ia.getLocalizedMessage());
            }
        }
    }

    private void setHttpProxy(Builder builder) {
        if (mProxyInfo != null && Build.VERSION.SDK_INT >= 29) {
            builder.setHttpProxy(mProxyInfo);
        } else if (mProxyInfo != null) {
            VpnStatus.logWarning("HTTP Proxy needs Android 10 or later.");
        }
    }

    private boolean isLockdownEnabledCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return isLockdownEnabled();
        } else {
            /* We cannot determine this, return false */
            return false;
        }

    }

    private void allowAllAFFamilies(Builder builder) {
        builder.allowFamily(OsConstants.AF_INET);
        builder.allowFamily(OsConstants.AF_INET6);
    }

    private void setAllowedVpnPackages(Builder builder) {
        boolean atLeastOneAllowedApp = false;

        for (String pkg : mProfile.mAllowedAppsVpn) {
            try {
                if (mProfile.mAllowedAppsVpnAreDisallowed) {
                    builder.addDisallowedApplication(pkg);
                } else {
                    builder.addAllowedApplication(pkg);
                    atLeastOneAllowedApp = true;
                }
            } catch (PackageManager.NameNotFoundException e) {
                mProfile.mAllowedAppsVpn.remove(pkg);
                VpnStatus.logInfo(R.string.app_no_longer_exists, pkg);
            }
        }

        if (!mProfile.mAllowedAppsVpnAreDisallowed && !atLeastOneAllowedApp) {
            VpnStatus.logDebug(R.string.no_allowed_app, getPackageName());
            try {
                builder.addAllowedApplication(getPackageName());
            } catch (PackageManager.NameNotFoundException e) {
                VpnStatus.logError("This should not happen: " + e.getLocalizedMessage());
            }
        }

        if (mProfile.mAllowedAppsVpnAreDisallowed) {
            VpnStatus.logDebug(R.string.disallowed_vpn_apps_info, TextUtils.join(", ", mProfile.mAllowedAppsVpn));
        } else {
            VpnStatus.logDebug(R.string.allowed_vpn_apps_info, TextUtils.join(", ", mProfile.mAllowedAppsVpn));
        }

        if (mProfile.mAllowAppVpnBypass) {
            builder.allowBypass();
            VpnStatus.logDebug("Apps may bypass VPN");
        }
    }

    public void addDNS(String dns) {
        mDnslist.add(dns);
    }

    public void setDomain(String domain) {
        if (mDomain == null) {
            mDomain = domain;
        }
    }

    /**
     * Route that is always included, used by the v3 core
     */
    public void addRoute(CIDRIP route, boolean include) {
        mRoutes.addIP(route, include);
    }

    public boolean addHttpProxy(String proxy, int port) {
        try {
            mProxyInfo = ProxyInfo.buildDirectProxy(proxy, port);
        } catch (Exception e) {
            VpnStatus.logError("Could not set proxy" + e.getLocalizedMessage());
            return false;
        }
        return true;
    }

    public void addRoute(String dest, String mask, String gateway, String device) {
        CIDRIP route = new CIDRIP(dest, mask);
        boolean include = isAndroidTunDevice(device);

        IpAddress gatewayIP = new IpAddress(new CIDRIP(gateway, 32), false);

        if (mLocalIP == null) {
            VpnStatus.logError("Local IP address unset and received. Neither pushed server config nor local config specifies an IP addresses. Opening tun device is most likely going to fail.");
            return;
        }
        IpAddress localNet = new IpAddress(mLocalIP, true);
        if (localNet.containsNet(gatewayIP))
            include = true;

        if (gateway != null && gateway.equals("255.255.255.255"))
            include = true;

        if (route.len == 32 && !mask.equals("255.255.255.255")) {
            VpnStatus.logWarning(R.string.route_not_cidr, dest, mask);
        }

        if (route.normalise())
            VpnStatus.logWarning(R.string.route_not_netip, dest, route.len, route.mIp);

        mRoutes.addIP(route, include);
    }

    public void addRoutev6(String network, String device) {
        // Tun is opened after ROUTE6, no device name may be present
        boolean included = isAndroidTunDevice(device);
        addRoutev6(network, included);
    }

    public void addRoutev6(String network, boolean included) {
        String[] v6parts = network.split("/");

        try {
            Inet6Address ip = (Inet6Address) InetAddress.getAllByName(v6parts[0])[0];
            int mask = Integer.parseInt(v6parts[1]);
            mRoutesv6.addIPv6(ip, mask, included);

        } catch (UnknownHostException e) {
            VpnStatus.logException(e);
        }


    }

    private boolean isAndroidTunDevice(String device) {
        return device != null &&
                (device.startsWith("tun") || "(null)".equals(device) || VPNSERVICE_TUN.equals(device));
    }

    public void setMtu(int mtu) {
        mMtu = mtu;
    }

    public void setLocalIP(CIDRIP cdrip) {
        mLocalIP = cdrip;
    }

    public void setLocalIPv6(String ipv6addr) {
        mLocalIPv6 = ipv6addr;
    }

    @Override
    public void updateState(String state, String logmessage, int resid, ConnectionStatus level, Intent intent) {
        Log.i(TAG, "updateState called, state = " + state);
        // If the process is not running, ignore any state,
        // Notification should be invisible in this state

        String channel = NOTIFICATION_CHANNEL_NEWSTATUS_ID;
        // Display byte count only after being connected

        {
            if (level == LEVEL_CONNECTED) {
                mDisplayBytecount = true;
                mConnecttime = System.currentTimeMillis();
                channel = NOTIFICATION_CHANNEL_BG_ID;
            } else {
                mDisplayBytecount = false;
            }

            // Other notifications are shown,
            // This also mean we are no longer connected, ignore bytecount messages until next
            // CONNECTED
            // Does not work :(
            showNotification(VpnStatus.getLastCleanLogMessage(this),
                    VpnStatus.getLastCleanLogMessage(this), channel, 0, level, intent);

        }
    }

    @Override
    public void setConnectedVPN(String uuid) {
    }

    @Override
    public void updateByteCount(long in, long out, long diffIn, long diffOut) {
        Log.i(TAG, String.format("updateByteCount called, in = %d, out = %d", in, out));
        if (mDisplayBytecount) {
            String netstat = String.format(getString(R.string.statusline_bytecount),
                    humanReadableByteCount(in, false, getResources()),
                    humanReadableByteCount(diffIn / OpenVPNManagement.mBytecountInterval, true, getResources()),
                    humanReadableByteCount(out, false, getResources()),
                    humanReadableByteCount(diffOut / OpenVPNManagement.mBytecountInterval, true, getResources()));


            showNotification(netstat, null, NOTIFICATION_CHANNEL_BG_ID, mConnecttime, LEVEL_CONNECTED, null);
        }
    }

    @Override
    public boolean handleMessage(Message msg) {
        Runnable r = msg.getCallback();
        if (r != null) {
            r.run();
            return true;
        } else {
            return false;
        }
    }

    public OpenVPNManagement getManagement() {
        return mManagement;
    }
}
