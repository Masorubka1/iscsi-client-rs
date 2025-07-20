iscsi-client-rs

A pure-Rust iSCSI initiator library and CLI for interacting with iSCSI targets.  It lets you build and send iSCSI PDUs, perform login (including CHAP), and exchange SCSI commands over TCP.

## WARNING ALL CODE TESTED ONLY WITH `targetcli`. ON OTHER TARGETS BEHAVIOUR UNEXPECTED

⸻

Features
	•	Build and parse iSCSI Login PDUs (Security, Operational, Full-Feature phases)
	•	CHAP authentication support (MD5 or HMAC-MD5)
	•	High-level Rust API for login and command exchange
	•	Async I/O with Tokio
	•	No external C dependencies
