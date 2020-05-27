#ifndef SWITCH_NODE_H
#define SWITCH_NODE_H

#include <unordered_map>
#include <ns3/node.h>
#include "qbb-net-device.h"
#include "switch-mmu.h"

namespace ns3 {
struct stat_tx_ {
	uint64_t txUimpBytes = 0;
	uint64_t txImpBytes = 0;
	uint64_t txImpEBytes = 0;
	uint64_t txUimpBytesNIC = 0;
	uint64_t txImpBytesNIC = 0;
	uint64_t txImpBytesNIC_PL = 0;
	uint64_t txImpBytesNIC_PLR = 0;
	uint64_t txImpBytesNIC_PLE = 0;
	uint64_t txImpBytesNIC_CNP = 0;
	uint64_t txImpBytesNIC_ACK = 0;
	uint64_t txImpBytesNIC_NACK = 0;
	uint64_t txImpEBytesNIC = 0;
	uint64_t txImpFBytesNIC = 0;
	uint64_t txImpEFBytesNIC = 0;
	uint64_t txImpCBytesNIC = 0;
	uint64_t txTltDropBytes = 0;
	uint64_t importantDropBytes = 0;
	uint64_t importantDropCnt = 0;
	uint64_t RetxTimeoutCnt = 0;
	uint64_t PauseSendCnt = 0;
	bool stat_print = false;
};

class Packet;

class SwitchNode : public Node{
	static const unsigned qCnt = 8;	// Number of queues/priorities used
	static const unsigned pCnt = 128; // port 0 is not used so + 1	// Number of ports used
	uint32_t m_ecmpSeed;
	std::unordered_map<uint32_t, std::vector<int> > m_rtTable; // map from ip address (u32) to possible ECMP port (index of dev)

	// monitor of PFC
	uint32_t m_bytes[pCnt][pCnt][qCnt]; // m_bytes[inDev][outDev][qidx] is the bytes from inDev enqueued for outDev at qidx
	
	uint64_t m_txBytes[pCnt]; // counter of tx bytes

protected:
	bool m_ecnEnabled;
	uint32_t m_ccMode;

	uint32_t m_ackHighPrio; // set high priority for ACK/NACK

private:
	int GetOutDev(Ptr<const Packet>, CustomHeader &ch);
	void SendToDev(Ptr<Packet>p, CustomHeader &ch);
	static uint32_t EcmpHash(const uint8_t* key, size_t len, uint32_t seed);
	void CheckAndSendPfc(uint32_t inDev, uint32_t qIndex);
	void CheckAndSendResume(uint32_t inDev, uint32_t qIndex);
public:
	//Ptr<BroadcomNode> m_broadcom;
	Ptr<SwitchMmu> m_mmu;

	static TypeId GetTypeId (void);
	SwitchNode();
	void SetEcmpSeed(uint32_t seed);
	void AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx);
	void ClearTable();
	bool SwitchReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet, CustomHeader &ch);
	void SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p);
};

} /* namespace ns3 */

#endif /* SWITCH_NODE_H */
