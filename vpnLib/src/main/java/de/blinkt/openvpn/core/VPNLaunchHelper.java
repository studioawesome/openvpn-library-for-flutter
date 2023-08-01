/*
 * Copyright (c) 2012-2016 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.core;

import android.content.Context;
import android.content.Intent;
import android.os.Build;

import de.blinkt.openvpn.VpnProfile;

public class VPNLaunchHelper {
    public static void startOpenVpn(VpnProfile startprofile, Context context, String startReason) {
        Intent startVPN = startprofile.getStartServiceIntent(context, startReason);
        if (startVPN != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                //noinspection NewApi
                context.startForegroundService(startVPN);
            else
                context.startService(startVPN);

        }
    }
}
