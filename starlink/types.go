package starlink

// StarLinkInfo represents information gathered from a Starlink Dishy
type StarLinkInfo struct {
	Accessible    bool                   `json:"accessible"`
	DeviceInfo    *DeviceInfo           `json:"device_info,omitempty"`
	Status        *DishStatus           `json:"status,omitempty"`
	Config        *DishConfig           `json:"config,omitempty"`
	SecurityIssues []SecurityIssue      `json:"security_issues"`
}

// DeviceInfo contains basic device identification
type DeviceInfo struct {
	ID              string `json:"id"`
	HardwareVersion string `json:"hardware_version"`
	SoftwareVersion string `json:"software_version"`
	CountryCode     string `json:"country_code"`
	BootCount       int    `json:"boot_count"`
	BuildID         string `json:"build_id"`
}

// DishStatus contains operational status information
type DishStatus struct {
	UptimeS                 int64   `json:"uptime_s"`
	DownlinkThroughputBps   float64 `json:"downlink_throughput_bps"`
	UplinkThroughputBps     float64 `json:"uplink_throughput_bps"`
	PopPingLatencyMs        float64 `json:"pop_ping_latency_ms"`
	BoresightAzimuthDeg     float64 `json:"boresight_azimuth_deg"`
	BoresightElevationDeg   float64 `json:"boresight_elevation_deg"`
	EthSpeedMbps            int     `json:"eth_speed_mbps"`
	ConnectedRouters        []string `json:"connected_routers"`
	HasActuators            string  `json:"has_actuators"`
	DisablementCode         string  `json:"disablement_code"`
	SoftwareUpdateState     string  `json:"software_update_state"`
}

// DishConfig contains configuration settings
type DishConfig struct {
	SwupdateRebootHour                    int  `json:"swupdate_reboot_hour"`
	ApplySnowMeltMode                     bool `json:"apply_snow_melt_mode"`
	ApplyLocationRequestMode              bool `json:"apply_location_request_mode"`
	ApplyLevelDishMode                    bool `json:"apply_level_dish_mode"`
	ApplyPowerSaveStartMinutes            bool `json:"apply_power_save_start_minutes"`
	ApplyPowerSaveDurationMinutes         bool `json:"apply_power_save_duration_minutes"`
	ApplyPowerSaveMode                    bool `json:"apply_power_save_mode"`
	ApplySwupdateThreeDayDeferralEnabled  bool `json:"apply_swupdate_three_day_deferral_enabled"`
	ApplyAssetClass                       bool `json:"apply_asset_class"`
	ApplySwupdateRebootHour               bool `json:"apply_swupdate_reboot_hour"`
}

// SecurityIssue represents a security finding related to Starlink
type SecurityIssue struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Remediation string `json:"remediation"`
}

// gRPC response structures for parsing JSON responses
type GRPCResponse struct {
	APIVersion    string               `json:"apiVersion"`
	DishGetStatus *DishGetStatusResp   `json:"dishGetStatus,omitempty"`
	GetDeviceInfo *GetDeviceInfoResp   `json:"getDeviceInfo,omitempty"`
	DishGetConfig *DishGetConfigResp   `json:"dishGetConfig,omitempty"`
}

type DishGetStatusResp struct {
	DeviceInfo             DeviceInfoResp      `json:"deviceInfo"`
	DeviceState            DeviceStateResp     `json:"deviceState"`
	DownlinkThroughputBps  float64            `json:"downlinkThroughputBps"`
	UplinkThroughputBps    float64            `json:"uplinkThroughputBps"`
	PopPingLatencyMs       float64            `json:"popPingLatencyMs"`
	BoresightAzimuthDeg    float64            `json:"boresightAzimuthDeg"`
	BoresightElevationDeg  float64            `json:"boresightElevationDeg"`
	EthSpeedMbps           int                `json:"ethSpeedMbps"`
	ConnectedRouters       []string           `json:"connectedRouters"`
	HasActuators           string             `json:"hasActuators"`
	DisablementCode        string             `json:"disablementCode"`
	SoftwareUpdateState    string             `json:"softwareUpdateState"`
}

type DeviceInfoResp struct {
	ID              string `json:"id"`
	HardwareVersion string `json:"hardwareVersion"`
	SoftwareVersion string `json:"softwareVersion"`
	CountryCode     string `json:"countryCode"`
	BootCount       int    `json:"bootcount"`
	BuildID         string `json:"buildId"`
}

type DeviceStateResp struct {
	UptimeS string `json:"uptimeS"`
}

type GetDeviceInfoResp struct {
	DeviceInfo DeviceInfoResp `json:"deviceInfo"`
}

type DishGetConfigResp struct {
	DishConfig DishConfigResp `json:"dishConfig"`
}

type DishConfigResp struct {
	SwupdateRebootHour                    int  `json:"swupdateRebootHour"`
	ApplySnowMeltMode                     bool `json:"applySnowMeltMode"`
	ApplyLocationRequestMode              bool `json:"applyLocationRequestMode"`
	ApplyLevelDishMode                    bool `json:"applyLevelDishMode"`
	ApplyPowerSaveStartMinutes            bool `json:"applyPowerSaveStartMinutes"`
	ApplyPowerSaveDurationMinutes         bool `json:"applyPowerSaveDurationMinutes"`
	ApplyPowerSaveMode                    bool `json:"applyPowerSaveMode"`
	ApplySwupdateThreeDayDeferralEnabled  bool `json:"applySwupdateThreeDayDeferralEnabled"`
	ApplyAssetClass                       bool `json:"applyAssetClass"`
	ApplySwupdateRebootHour               bool `json:"applySwupdateRebootHour"`
}