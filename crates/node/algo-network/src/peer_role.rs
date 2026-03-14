//! Peer roles and role-set management.
//!
//! Mirrors go-algorand's `network/phonebook/phonebook.go` role types.
//! Each phonebook entry can hold one or more roles (relay, archival) as a
//! bitfield, with an independent persistence bitfield tracking which roles
//! survive peer-list replacements.

/// A single role that a phonebook entry can have.
///
/// Roles are represented as individual bits so they can be combined into a
/// bitfield inside [`RoleSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Role(pub u8);

/// Relay nodes provided via the algobootstrap SRV record or configuration file.
pub const RELAY_ROLE: Role = Role(1);

/// Archival nodes provided via the archive SRV record.
pub const ARCHIVAL_ROLE: Role = Role(2);

/// A set of roles with independent persistence tracking.
///
/// `roles` is a bitfield of the roles this entry currently holds.
/// `persistence` is a bitfield of the roles that are marked as persistent
/// (i.e., survive peer-list replacements).
#[derive(Debug, Clone, Default)]
pub struct RoleSet {
    /// Bitfield of active roles.
    roles: u8,
    /// Bitfield of roles marked as persistent.
    persistence: u8,
}

impl RoleSet {
    /// Creates a new `RoleSet` with the given role.
    ///
    /// If `persistent` is true, the role is also marked as persistent.
    pub fn new(role: Role, persistent: bool) -> Self {
        let mut rs = RoleSet {
            roles: role.0,
            persistence: 0,
        };
        if persistent {
            rs.persistence = role.0;
        }
        rs
    }

    /// Returns `true` if this role set contains the given role (bitwise AND).
    pub fn has(&self, other: Role) -> bool {
        self.roles & other.0 != 0
    }

    /// Returns `true` if this role set is exactly equal to the given role.
    pub fn is(&self, other: Role) -> bool {
        self.roles == other.0
    }

    /// Adds the given role to this set (bitwise OR).
    pub fn add(&mut self, other: Role) {
        self.roles |= other.0;
    }

    /// Removes the given role from this set (bitwise AND NOT).
    pub fn remove(&mut self, other: Role) {
        self.roles &= !other.0;
    }

    /// Adds a role and marks it as persistent.
    pub fn add_persistent(&mut self, role: Role) {
        self.roles |= role.0;
        self.persistence |= role.0;
    }

    /// Returns `true` if the given role is marked as persistent.
    pub fn is_persistent(&self, role: Role) -> bool {
        self.persistence & role.0 != 0
    }

    /// Returns `true` if any role in this set is marked as persistent.
    pub fn has_persistent_roles(&self) -> bool {
        self.persistence != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Role constants
    // -----------------------------------------------------------------------

    #[test]
    fn role_constants_are_correct() {
        assert_eq!(RELAY_ROLE.0, 1);
        assert_eq!(ARCHIVAL_ROLE.0, 2);
    }

    #[test]
    fn roles_are_distinct_bits() {
        assert_eq!(RELAY_ROLE.0 & ARCHIVAL_ROLE.0, 0);
    }

    // -----------------------------------------------------------------------
    // RoleSet::new
    // -----------------------------------------------------------------------

    #[test]
    fn new_sets_role() {
        let rs = RoleSet::new(RELAY_ROLE, false);
        assert!(rs.has(RELAY_ROLE));
        assert!(!rs.has(ARCHIVAL_ROLE));
    }

    #[test]
    fn new_persistent_marks_persistence() {
        let rs = RoleSet::new(RELAY_ROLE, true);
        assert!(rs.has(RELAY_ROLE));
        assert!(rs.is_persistent(RELAY_ROLE));
        assert!(rs.has_persistent_roles());
    }

    #[test]
    fn new_non_persistent() {
        let rs = RoleSet::new(RELAY_ROLE, false);
        assert!(!rs.is_persistent(RELAY_ROLE));
        assert!(!rs.has_persistent_roles());
    }

    // -----------------------------------------------------------------------
    // RoleSet::default
    // -----------------------------------------------------------------------

    #[test]
    fn default_is_empty() {
        let rs = RoleSet::default();
        assert!(!rs.has(RELAY_ROLE));
        assert!(!rs.has(ARCHIVAL_ROLE));
        assert!(!rs.has_persistent_roles());
    }

    // -----------------------------------------------------------------------
    // has / is
    // -----------------------------------------------------------------------

    #[test]
    fn has_checks_bitwise() {
        let mut rs = RoleSet::new(RELAY_ROLE, false);
        rs.add(ARCHIVAL_ROLE);
        assert!(rs.has(RELAY_ROLE));
        assert!(rs.has(ARCHIVAL_ROLE));
    }

    #[test]
    fn is_checks_exact_equality() {
        let rs = RoleSet::new(RELAY_ROLE, false);
        assert!(rs.is(RELAY_ROLE));
        assert!(!rs.is(ARCHIVAL_ROLE));
    }

    #[test]
    fn is_fails_when_multiple_roles() {
        let mut rs = RoleSet::new(RELAY_ROLE, false);
        rs.add(ARCHIVAL_ROLE);
        // has both, so is(RelayRole) alone should be false
        assert!(!rs.is(RELAY_ROLE));
        assert!(!rs.is(ARCHIVAL_ROLE));
    }

    // -----------------------------------------------------------------------
    // add / remove
    // -----------------------------------------------------------------------

    #[test]
    fn add_sets_role_bit() {
        let mut rs = RoleSet::new(RELAY_ROLE, false);
        assert!(!rs.has(ARCHIVAL_ROLE));
        rs.add(ARCHIVAL_ROLE);
        assert!(rs.has(ARCHIVAL_ROLE));
    }

    #[test]
    fn remove_clears_role_bit() {
        let mut rs = RoleSet::new(RELAY_ROLE, false);
        rs.add(ARCHIVAL_ROLE);
        rs.remove(RELAY_ROLE);
        assert!(!rs.has(RELAY_ROLE));
        assert!(rs.has(ARCHIVAL_ROLE));
    }

    #[test]
    fn remove_nonexistent_role_is_noop() {
        let mut rs = RoleSet::new(RELAY_ROLE, false);
        rs.remove(ARCHIVAL_ROLE);
        assert!(rs.has(RELAY_ROLE));
        assert!(!rs.has(ARCHIVAL_ROLE));
    }

    #[test]
    fn add_idempotent() {
        let mut rs = RoleSet::new(RELAY_ROLE, false);
        rs.add(RELAY_ROLE);
        assert!(rs.is(RELAY_ROLE));
    }

    // -----------------------------------------------------------------------
    // add_persistent / is_persistent / has_persistent_roles
    // -----------------------------------------------------------------------

    #[test]
    fn add_persistent_sets_both_role_and_persistence() {
        let mut rs = RoleSet::new(RELAY_ROLE, false);
        rs.add_persistent(ARCHIVAL_ROLE);

        assert!(rs.has(ARCHIVAL_ROLE));
        assert!(rs.is_persistent(ARCHIVAL_ROLE));
        // relay was added non-persistent, should remain non-persistent
        assert!(!rs.is_persistent(RELAY_ROLE));
        assert!(rs.has(RELAY_ROLE));
        assert!(rs.has_persistent_roles());
    }

    #[test]
    fn multiple_roles_with_different_persistence() {
        // Mirrors Go's "Multiple roles with different persistence" test
        let mut rs = RoleSet::new(RELAY_ROLE, true);
        rs.add(ARCHIVAL_ROLE);

        assert!(rs.is_persistent(RELAY_ROLE));
        assert!(!rs.is_persistent(ARCHIVAL_ROLE));
        assert!(rs.has(RELAY_ROLE));
        assert!(rs.has(ARCHIVAL_ROLE));
    }

    #[test]
    fn is_persistent_false_for_absent_role() {
        let rs = RoleSet::new(RELAY_ROLE, true);
        assert!(!rs.is_persistent(ARCHIVAL_ROLE));
    }

    // -----------------------------------------------------------------------
    // Clone
    // -----------------------------------------------------------------------

    #[test]
    fn clone_is_independent() {
        let mut rs = RoleSet::new(RELAY_ROLE, true);
        let mut cloned = rs.clone();
        cloned.add(ARCHIVAL_ROLE);
        // original should be unaffected
        assert!(!rs.has(ARCHIVAL_ROLE));
        // cloned should have it
        assert!(cloned.has(ARCHIVAL_ROLE));

        // and mutating original should not affect clone
        rs.remove(RELAY_ROLE);
        assert!(cloned.has(RELAY_ROLE));
    }

    // -----------------------------------------------------------------------
    // Combined role values
    // -----------------------------------------------------------------------

    #[test]
    fn combined_role_value() {
        let mut rs = RoleSet::default();
        rs.add(RELAY_ROLE);
        rs.add(ARCHIVAL_ROLE);
        // internal roles field should be 1 | 2 = 3
        assert!(rs.has(RELAY_ROLE));
        assert!(rs.has(ARCHIVAL_ROLE));
        assert!(!rs.is(RELAY_ROLE));
        assert!(!rs.is(ARCHIVAL_ROLE));
    }

    // -----------------------------------------------------------------------
    // Remove does not affect persistence
    // -----------------------------------------------------------------------

    #[test]
    fn remove_does_not_clear_persistence() {
        let mut rs = RoleSet::new(RELAY_ROLE, true);
        rs.remove(RELAY_ROLE);
        // Role is removed from the active set
        assert!(!rs.has(RELAY_ROLE));
        // But persistence bit remains (matches Go behavior: Remove only
        // touches the roles bitfield, not persistence)
        assert!(rs.is_persistent(RELAY_ROLE));
    }
}
