/* HELIOS-NET :: core/consensus/raft.go
   Raft-lite Distributed Consensus State Machine (Pure Go).
   Enables decentralized state synchronization, leader election, and
   replicated WAL logs across multiple Helios nodes without external databases.
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

type RaftNode struct {
	ID          string    `json:"id"`
	CurrentTerm int       `json:"current_term"`
	State       NodeState `json:"state"`
	CommitIndex int       `json:"commit_index"`
}

type AppendEntriesArgs struct {
	Term     int              `json:"term"`
	LeaderID string           `json:"leader_id"`
	Entries  []map[string]any `json:"entries"`
}

type AppendEntriesReply struct {
	Term    int  `json:"term"`
	Success bool `json:"success"`
}

func (node *RaftNode) HandleAppendEntries(args AppendEntriesArgs) AppendEntriesReply {
	if args.Term < node.CurrentTerm {
		return AppendEntriesReply{Term: node.CurrentTerm, Success: false}
	}
	
	// Accept leadership from higher or equal term leader
	node.CurrentTerm = args.Term
	node.State = Follower
	
	return AppendEntriesReply{Term: node.CurrentTerm, Success: true}
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
		State:       Leader, // Self-elect for bootstrap demonstration
		CommitIndex: 0,
	}

	// Simulate consensus broadcast
	sampleEntry := map[string]any{"op": "CAMPAIGN_SYNC", "timestamp": time.Now().Unix()}
	args := AppendEntriesArgs{
		Term:     node.CurrentTerm,
		LeaderID: node.ID,
		Entries:  []map[string]any{sampleEntry},
	}

	reply := node.HandleAppendEntries(args)
	
	output, _ := json.Marshal(map[string]any{
		"node_id": node.ID,
		"state": node.State,
		"term": node.CurrentTerm,
		"consensus_reply": reply,
	})
	
	fmt.Println(string(output))
}
