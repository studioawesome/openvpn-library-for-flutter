package de.blinkt.openvpn;

public interface OnVPNStatusChangeListener {
    void onVPNEventReceived(VPNEvent event);

    void onConnectionInfoChanged(long byteIn, long byteOut);
}
