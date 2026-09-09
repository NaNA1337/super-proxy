package scheduler

type SlotState string

const (
	SlotOffline   SlotState = "OFFLINE"
	SlotPreparing SlotState = "PREPARING"
	SlotConnecting SlotState = "CONNECTING"
	SlotVerifying SlotState = "VERIFYING"
	SlotActive    SlotState = "ACTIVE"
	SlotDraining  SlotState = "DRAINING"
	SlotFailed    SlotState = "FAILED"
)
