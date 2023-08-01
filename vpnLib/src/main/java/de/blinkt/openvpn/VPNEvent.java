package de.blinkt.openvpn;

public enum VPNEvent {
    NOPROCESS,
    VPN_GENERATE_CONFIG,
    RESOLVE,
    WAIT,
    CONNECTING,
    GET_CONFIG,
    ASSIGN_IP,
    CONNECTED,
    DISCONNECTED,
    DISCONNECTING,
    RECONNECTING,
    AUTH_FAILED,
    PAUSE,
    RESUME
}
