/*
 * FIP — Forensic Isolation Program. C4 model in Structurizr DSL.
 *
 * Render:
 *   docker run -it --rm -p 8080:8080 -v "$PWD:/usr/local/structurizr" \
 *     structurizr/lite
 *   then open http://localhost:8080
 *
 * Scope note: this models what is BUILT. Memory capture, detonation,
 * automatic triggering and automated evidence delivery into the analysis
 * account are designed but not implemented, and are deliberately absent —
 * see docs/MANUAL.md §13.
 */
workspace "FIP" "Forensic Isolation Program — acquire, isolate and attest EC2 evidence" {

    model {
        responder = person "Incident Responder" {
            description "Starts a case and decides containment posture. The only human in the acquisition path."
        }

        examiner = person "Forensic Examiner" {
            description "Analyzes acquired evidence. May be a third party outside the organization."
        }

        organizations = softwareSystem "AWS Organizations" "Optional. Resolves account ids by name at install time." "External"

        compromised = softwareSystem "Member AWS Account" {
            description "A potentially compromised workload account. FIP acts on it and never runs inside it."
            tags "External"

            instance = container "Suspect EC2 Instance" "The acquisition target, with its EBS volumes and network interfaces" "EC2" "Target"
            memberKey = container "Customer EBS CMK" "The customer's own key. FIP never tags it and cannot delete it." "KMS" "Target"
            asg       = container "Auto Scaling Group" "Would otherwise replace or reap the instance mid-case" "EC2 Auto Scaling" "Target"
        }

        fip = softwareSystem "FIP" {
            description "Isolates a suspect instance, acquires a forensic copy, moves it to a dedicated account and signs a chain-of-custody manifest."

            group "Orchestrator Account" {
                caseMachine  = container "FipCase" "The execution a responder starts. Fans out over targets; a failed target is recorded, not fatal." "AWS Step Functions (Standard)" "Orchestration"
                stateMachine = container "FipAcquisition" "One instance in one account. Orders the case and holds the execution history that becomes part of the record" "AWS Step Functions (Standard)" "Orchestration"
                memberAction = container "member-action" "Every call into a member or evidence account. Assumes roles; performs one action per invocation." "AWS Lambda (Node 24)" "Compute" {
                    credentials = component "Credential Broker" "Two paths: FipResponderRole with an external ID, FipEvidenceRole without." "memberCredentials / evidenceCredentials"
                    tagging     = component "Tagging" "Tags instance, volumes and interfaces. Must be first - every later permission is scoped by the tag." "tagTarget"
                    containment = component "Containment" "Finds or creates the isolation group, records ORIGINAL security groups, detaches from Auto Scaling." "containInstance / isolationGroupFor"
                    acquisition = component "Acquisition" "Crash-consistent multi-volume snapshot, born tagged. Idempotent by case." "createSnapshots / snapshotStatus"
                    hashing     = component "Hashing" "Splits a snapshot into bounded ranges and combines range digests into a Merkle root." "hashPlan / hashRange / hashCombine"
                    transfer    = component "Evidence Transfer" "Grants key access, shares, then copies into the evidence account re-encrypted." "shareToEvidence / copyToEvidence"
                    manifest    = component "Manifest" "Builds, signs and stores the chain-of-custody record. One manifest per INSTANCE, under the case prefix." "writeManifest"
                    caseRecord  = component "Case Record" "Opens the case row with an empty targets map, then rolls per-target outcomes up to ACQUIRED / PARTIAL / FAILED." "caseOpen / caseSummary"
                    custody     = component "Evidence Release" "Shares evidence to the analysis account and grants the forensic key, or withdraws both. NOT reachable from the state machines - a human decides, per case." "releaseToAnalysis"
                    halt        = component "Stop" "Stops the instance. Service-affecting and loses instance-store data." "stopInstance"
                }
                signingKey   = container "Manifest Signing Key" "ECC_NIST_P384, sign/verify only. Verifiable outside AWS." "AWS KMS" "Crypto"
            }

            group "Evidence Account" {
                evidenceBucket = container "Evidence Bucket" "Object Lock ENABLED, no default retention. Signed manifests." "Amazon S3" "Store"
                caseTable      = container "Case Table" "Case state and manifest pointer" "Amazon DynamoDB" "Store"
                evidenceKey    = container "Forensic CMK" "Evidence is re-encrypted under this key on copy" "AWS KMS" "Crypto"
                retentionParam = container "Retention Policy" "Whether anything is locked, and for how long. Customer-supplied." "AWS SSM Parameter" "Store"
                evidenceRole   = container "FipEvidenceRole" "Copies snapshots IN and writes manifests. No delete, no retention change." "IAM Role" "Identity"
                responderTopic = container "Responder Topic" "Case notifications and approval task tokens. Customer subscribes their own handler." "Amazon SNS" "Messaging"
            }

            group "Analysis Account (optional, may be a third party's)" {
                analysisVpc    = container "Isolated VPC" "Private subnets only. No internet gateway, no NAT, NO ROUTE off the VPC - so evidence that executes cannot phone home." "Amazon VPC" "Network"
                ssmEndpoints   = container "SSM Interface Endpoints" "ssm, ssmmessages, ec2messages. The only things the workstation can reach." "VPC Endpoints" "Network"
                workstation    = container "Examiner Workstation" "No public IP, no inbound rules, NO KEY PAIR. Reached only by Session Manager." "EC2 (Amazon Linux 2023)" "Compute"
                sessionDoc     = container "FipForensicSession" "Custom Session document carrying the logging config. The account default is never overwritten." "SSM Document" "Identity"
                sessionLogs    = container "Session Transcripts" "Keystroke-level, to S3 and CloudWatch, KMS-encrypted. The examiner cannot delete from it." "Amazon S3 + CloudWatch Logs" "Store"
                examinerRole   = container "FipExaminerRole" "Opens a logged session on ONE instance with ONE document. Denied every route to altering the audit trail." "IAM Role" "Identity"
            }

            group "Member Account (deployed into each)" {
                inventoryRole = container "FipInventoryRole" "Read-only. Assumed constantly, changes nothing." "IAM Role" "Identity"
                responderRole = container "FipResponderRole" "Mutating. Tag, snapshot, contain, stop. Bounded by a permissions boundary." "IAM Role" "Identity"
                isolationGroup = container "Isolation Security Group" "No ingress, no egress. One per VPC, created on demand." "EC2 Security Group" "Identity"
            }
        }

        # --- system context ---
        responder -> fip "Starts a case; chooses whether to stop the instance"
        fip -> compromised "Isolates, snapshots and detaches from Auto Scaling"
        fip -> responder "Notifies; requests approval for service-affecting steps"
        examiner -> fip "Reads evidence and verifies the signed manifest"
        organizations -> fip "Supplies account ids at install time"

        # --- container: orchestration ---
        responder -> caseMachine "bin/fip-isolate.sh — pre-flights every target, then StartExecution with the case id and the target list"
        caseMachine -> stateMachine "One nested .sync execution per target, 4 at a time. Catches per target."
        caseMachine -> caseRecord "action=caseOpen, caseSummary"
        stateMachine -> memberAction "Invokes once per action; retries transient failures only"
        stateMachine -> responderTopic "Publishes case events and task tokens"
        responderTopic -> responder "Notifies via the customer's own subscriber"

        # --- container: into the member account ---
        memberAction -> responderRole "sts:AssumeRole with a per-account external ID"
        memberAction -> inventoryRole "Assumes for read-only enumeration"
        responderRole -> instance "Tags, snapshots, applies isolation, optionally stops"
        responderRole -> isolationGroup "Creates on demand; strips its default egress rule"
        isolationGroup -> instance "Applied to every network interface"
        responderRole -> asg "DetachInstances so the group stops managing it"
        responderRole -> memberKey "Grants the evidence account use of it, so the snapshot can be shared"

        # --- container: evidence path ---
        memberAction -> evidenceRole "sts:AssumeRole. CopySnapshot must run in the destination account."
        evidenceRole -> evidenceKey "Re-encrypts the copy under the forensic key"
        evidenceRole -> evidenceBucket "Writes the signed manifest"
        evidenceRole -> caseTable "Records case state"
        memberAction -> signingKey "kms:Sign over the manifest"
        memberAction -> retentionParam "Reads whether to lock, and for how long"
        examiner -> evidenceBucket "Retrieves the manifest and verifies the signature"

        responder -> custody "bin/fip-release.sh - a deliberate chain-of-custody decision, never automatic"
        custody -> evidenceBucket "Writes a SIGNED custody record. A revoke never erases a release."
        custody -> caseTable "Appends a custody entry"
        custody -> evidenceKey "Grants Decrypt to the analysis account, or retires the grant"
        custody -> workstation "Shares the evidence snapshots so volumes can be created from them"
        custody -> credentials "evidence"

        examiner -> examinerRole "Assumes. Examiner access is an IAM permission, not a host to log into."
        examinerRole -> sessionDoc "ssm:StartSession, pinned to this document AND one instance"
        examinerRole -> workstation "Opens a logged session. No SSH, no RDP, no key."
        workstation -> ssmEndpoints "Dials OUT over HTTPS. Nothing dials in."
        workstation -> analysisVpc "Runs in a private isolated subnet"
        workstation -> sessionLogs "Appends the transcript. Cannot delete or decrypt it."

        # --- component relationships (inside member-action) ---
        stateMachine -> tagging "action=tag"
        stateMachine -> containment "action=contain"
        stateMachine -> halt "action=stop (only if requested)"
        stateMachine -> acquisition "action=snapshot / status"
        stateMachine -> hashing "action=hashPlan, hashRange x N, hashCombine"
        stateMachine -> transfer "action=share, copy, copyStatus"
        stateMachine -> manifest "action=manifest"

        tagging -> credentials "member"
        containment -> credentials "member"
        acquisition -> credentials "member"
        halt -> credentials "member"
        transfer -> credentials "member, then evidence"
        hashing -> credentials "member for source, evidence for the retained copy"
        manifest -> credentials "evidence"

        credentials -> responderRole "Assumes with external ID"
        credentials -> evidenceRole "Assumes"
        containment -> isolationGroup "Creates and applies"
        acquisition -> instance "CreateSnapshots"
        transfer -> evidenceKey "Re-encrypts under the forensic key"
        manifest -> signingKey "Signs"
        manifest -> evidenceBucket "Stores"
        manifest -> caseTable "Records, as a nested entry per target - concurrent targets cannot overwrite each other"
        caseRecord -> caseTable "Opens the case row, then writes the roll-up"
        caseRecord -> credentials "evidence"
    }

    views {
        systemContext fip "SystemContext" {
            include *
            autolayout lr
            description "Who uses FIP and what it acts on. FIP runs outside the compromised account, never inside it."
        }

        container fip "Containers" {
            include *
            autolayout lr
            description "Grouped by account. The account boundary is the security boundary: the orchestrator holds no evidence, and the evidence account is unreachable from the compromised environment."
        }

        component memberAction "MemberActionComponents" {
            include *
            autolayout lr
            description "One Lambda, one action per invocation. The Credential Broker is the only component that crosses an account boundary."
        }

        styles {
            element "Person" {
                shape person
                background "#1f4e79"
                color "#ffffff"
            }
            element "Software System" {
                background "#2e75b6"
                color "#ffffff"
            }
            element "External" {
                background "#9e9e9e"
                color "#ffffff"
            }
            element "Target" {
                background "#b03a2e"
                color "#ffffff"
            }
            element "Container" {
                background "#5b9bd5"
                color "#ffffff"
            }
            element "Orchestration" {
                shape hexagon
                background "#1f4e79"
                color "#ffffff"
            }
            element "Compute" {
                background "#2e75b6"
                color "#ffffff"
            }
            element "Store" {
                shape cylinder
                background "#548235"
                color "#ffffff"
            }
            element "Crypto" {
                shape hexagon
                background "#7030a0"
                color "#ffffff"
            }
            element "Identity" {
                shape roundedBox
                background "#bf8f00"
                color "#ffffff"
            }
            element "Messaging" {
                shape pipe
                background "#548235"
                color "#ffffff"
            }
            element "Component" {
                background "#85c1e9"
                color "#000000"
            }
        }
    }
}
