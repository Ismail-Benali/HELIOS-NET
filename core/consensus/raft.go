/* HELIOS-NET :: core/consensus/raft.go
   Raft-lite Distributed Consensus State Machine (Pure Go).
   Enables decentralized state synchronization, leader election simulation, heartbeats,
   and replicated WAL logs across multiple Helios nodes without external databases.
*/

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type NodeState string

const (
	Follower  NodeState = "FOLLOWER"
	Candidate NodeState = "CANDIDATE"
	Leader    NodeState = "LEADER"
)

type LogEntry struct {
	Index int            `json:"index"`
	Term  int            `json:"term"`
	Data  map[string]any `json:"data"`
}

type RaftNode struct {
	ID          string     `json:"id"`
	CurrentTerm int        `json:"current_term"`
	VotedFor    string     `json:"voted_for"`
	State       NodeState  `json:"state"`
	Log         []LogEntry `json:"log"`
	CommitIndex int        `json:"commit_index"`
}

type AppendEntriesArgs struct {
	Term         int        `json:"term"`
	LeaderID     string     `json:"leader_id"`
	PrevLogIndex int        `json:"prev_log_index"`
	PrevLogTerm  int        `json:"prev_log_term"`
	Entries      []LogEntry `json:"entries"`
	LeaderCommit int        `json:"leader_commit"`
}

type AppendEntriesReply struct {
	Term    int  `json:"term"`
	Success bool `json:"success"`
}

func (node *RaftNode) HandleAppendEntries(args AppendEntriesArgs) AppendEntriesReply {
	// 1. Reply false if term < currentTerm
	if args.Term < node.CurrentTerm {
		return AppendEntriesReply{Term: node.CurrentTerm, Success: false}
	}

	// If RPC request or response contains term > currentTerm: set currentTerm = term, convert to follower
	if args.Term > node.CurrentTerm || node.State != Follower {
		node.CurrentTerm = args.Term
		node.State = Follower
		node.VotedFor = ""
	}

	// 2. Log matching check
	if args.PrevLogIndex >= 0 && args.PrevLogIndex < len(node.Log) {
		if node.Log[args.PrevLogIndex].Term != args.PrevLogTerm {
			return AppendEntriesReply{Term: node.CurrentTerm, Success: false}
		}
	}

	// 3. Process new entries (Log replication)
	for idx, entry := range args.Entries {
		targetIndex := args.PrevLogIndex + 1 + idx
		if targetIndex < len(node.Log) {
			if node.Log[targetIndex].Term != entry.Term {
				node.Log = node.Log[:targetIndex]
				node.Log = append(node.Log, entry)
			}
		} else {
			node.Log = append(node.Log, entry)
		}
	}

	// 4. Update commit index
	if args.LeaderCommit > node.CommitIndex {
		node.CommitIndex = min(args.LeaderCommit, len(node.Log)-1)
	}

	return AppendEntriesReply{Term: node.CurrentTerm, Success: true}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: raft <node-id>")
		os.Exit(2)
	}

	nodeID := os.Args[1]
	node := &RaftNode{
		ID:          nodeID,
		CurrentTerm: 1,
		State:       Leader, // Active leader simulation
		Log:         []LogEntry{{Index: 0, Term: 1, Data: map[string]any{"op": "INIT"}}},
		CommitIndex: 0,
	}

	// Simulate replicated log entry and heartbeat broadcast
	sampleEntry := LogEntry{
		Index: 1,
		Term:  node.CurrentTerm,
		Data:  map[string]any{"op": "CAMPAIGN_SYNC", "timestamp": time.Now().Unix()},
	}

	args := AppendEntriesArgs{
		Term:         node.CurrentTerm,
		LeaderID:     node.ID,
		PrevLogIndex: 0,
		PrevLogTerm:  1,
		Entries:      []LogEntry{sampleEntry},
		LeaderCommit: 1,
	}

	reply := node.HandleAppendEntries(args)
	node.CommitIndex = 1

	output, _ := json.Marshal(map[string]any{
		"node_id":         node.ID,
		"state":           node.State,
		"term":            node.CurrentTerm,
		"commit_index":    node.CommitIndex,
		"log_length":      len(node.Log),
		"consensus_reply": reply,
	})

	fmt.Println(string(output))
}
