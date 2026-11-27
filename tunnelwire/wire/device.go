package wire

import (
	"github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

// DeviceRoute is the HTTPS twin of a device call: the request a relayed
// call stands for, whose method and URL the call's DPoP proof signs.
type DeviceRoute struct {
	Method string // HTTP method
	Path   string // path below the device API origin
	Param  bool   // path_suffix is a required path parameter
}

// DeviceRoutes maps every device method to its HTTPS twin.
var DeviceRoutes = map[tunnelpb.DeviceMethod]DeviceRoute{
	tunnelpb.DeviceMethod_REGISTER_APPS: {Method: "POST", Path: "/device/v2/apps"},
	tunnelpb.DeviceMethod_DELETE_APPS:   {Method: "POST", Path: "/device/v2/apps/delete"},
	tunnelpb.DeviceMethod_LIST_APPS:     {Method: "GET", Path: "/device/v2/apps"},
	tunnelpb.DeviceMethod_REPORT_HEALTH: {Method: "POST", Path: "/device/v2/health"},
	tunnelpb.DeviceMethod_ROTATE_KEY:    {Method: "POST", Path: "/device/v2/keys/rotate"},
	tunnelpb.DeviceMethod_SIGNED_TIME:   {Method: "POST", Path: "/device/v2/heartbeat"},
}

// TwinPath returns the HTTP method and path of a call's HTTPS twin.
func TwinPath(m tunnelpb.DeviceMethod, suffix string) (string, string, error) {
	r, ok := DeviceRoutes[m]
	if !ok {
		return "", "", fail(CodeBadValue, "method")
	}
	if !r.Param {
		if suffix != "" {
			return "", "", fail(CodeBadValue, "path_suffix")
		}
		return r.Method, r.Path, nil
	}
	if !ValidToken(suffix, MaxPathSuffix) {
		return "", "", fail(CodeBadValue, "path_suffix")
	}
	return r.Method, r.Path + "/" + suffix, nil
}
