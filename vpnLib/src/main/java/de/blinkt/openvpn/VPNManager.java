package de.blinkt.openvpn;

import android.annotation.TargetApi;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;

import java.io.IOException;
import java.io.StringReader;
import java.util.HashSet;
import java.util.List;

import de.blinkt.openvpn.core.ConfigParser;
import de.blinkt.openvpn.core.ConnectionStatus;
import de.blinkt.openvpn.core.ProfileManager;
import de.blinkt.openvpn.core.VPNLaunchHelper;
import de.blinkt.openvpn.core.VpnStatus;
import de.blinkt.openvpn.core.IOpenVPNServiceInternal;
import de.blinkt.openvpn.core.OpenVPNService;

public class VPNManager implements VpnStatus.StateListener, VpnStatus.ByteCountListener {
    private OnVPNStatusChangeListener listener;

    private IOpenVPNServiceInternal mService;
    private final ServiceConnection mConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName className, IBinder service) {
            mService = IOpenVPNServiceInternal.Stub.asInterface(service);
        }

        @Override
        public void onServiceDisconnected(ComponentName arg0) {
            mService = null;
        }
    };

    public VPNManager(Context context) {
        VpnStatus.initLogCache(context.getCacheDir());
    }

    public void setOnVPNStatusChangeListener(OnVPNStatusChangeListener listener) {
        this.listener = listener;
        VpnStatus.addStateListener(this);
        VpnStatus.addByteCountListener(this);
    }

    public Intent getPermissionIntent(Context context) {
        return VpnService.prepare(context);
    }

    public void bindVpnService(Context context) {
        Intent intent = new Intent(context, OpenVPNService.class);
        intent.setAction(OpenVPNService.START_SERVICE);
        context.bindService(intent, mConnection, Context.BIND_AUTO_CREATE);
    }

    public void unbindVpnService(Context context) {
        context.unbindService(mConnection);
    }

    public void disconnect() {
        if (mService != null) {
            try {
                mService.stopVPN(false);
            } catch (RemoteException e) {
                VpnStatus.logException(e);
            }
        }
    }

    public void connect(Context context, String config, String name, String username, String password, List<String> bypassPackages) {
        try {
            startVpn(context, config, name, username, password, bypassPackages);
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH_MR1)
    private void startVpn(Context context, String config, String name, String username, String password, List<String> bypassPackages) throws RemoteException {
        if (TextUtils.isEmpty(config)) throw new RemoteException("Config is empty");

        ConfigParser cp = new ConfigParser();
        try {
            cp.parseConfig(new StringReader(config));
            VpnProfile vp = cp.convertProfile();// Analysis.ovpn
            vp.mName = name;
            int checkResult = vp.checkProfile(context);
            if (checkResult != de.blinkt.openvpn.R.string.no_error_found) {
                throw new RemoteException(context.getString(checkResult));
            }
            vp.mProfileCreator = context.getPackageName();
            vp.mUsername = username;
            vp.mPassword = password;
            if (bypassPackages.size() > 0) {
                vp.mAllowAppVpnBypass = true;
                vp.mAllowedAppsVpn = new HashSet<>(bypassPackages);
            }

            ProfileManager.setTemporaryProfile(context, vp);
            VPNLaunchHelper.startOpenVpn(vp, context, "");
        } catch (IOException | ConfigParser.ConfigParseError e) {
            throw new RemoteException(e.getMessage());
        }
    }

    @Override
    public void updateState(String state, String logmessage, int localizedResId, ConnectionStatus level, Intent Intent) {
        try {
            listener.onVPNEventReceived(VPNEvent.valueOf(state));
        } catch(Exception e) {
            Log.e("VPNManager", String.format("Invalid VPNEvent value %s", state));
        }
    }

    @Override
    public void setConnectedVPN(String uuid) {

    }

    @Override
    public void updateByteCount(long in, long out, long diffIn, long diffOut) {
        listener.onConnectionInfoChanged(in, out);
    }
}