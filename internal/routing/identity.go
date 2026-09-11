package routing

const (
	// BaseTableID is the starting routing table ID and fwmark for active slot 0.
	BaseTableID = 100
	// BasePriority is the starting ip rule priority for slot routing rules.
	BasePriority = 100
)

// SlotIdentity encapsulates the unified routing numbers for a slot or candidate tunnel.
type SlotIdentity struct {
	Slot     int
	Mark     int
	TableID  int
	Priority int
}

// SlotRoutingIdentity returns the canonical routing identity (mark, table, priority)
// for any given slot index. This serves as the single source of truth across
// scheduler, benchmark, health, routing, and Xray supervisors.
func SlotRoutingIdentity(slot int) SlotIdentity {
	id := BaseTableID + slot
	return SlotIdentity{
		Slot:     slot,
		Mark:     id,
		TableID:  id,
		Priority: id,
	}
}
