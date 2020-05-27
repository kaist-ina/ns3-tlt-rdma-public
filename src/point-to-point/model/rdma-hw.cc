#include <ns3/simulator.h>
#include <ns3/seq-ts-header.h>
#include <ns3/udp-header.h>
#include <ns3/ipv4-header.h>
#include "ns3/ppp-header.h"
#include "ns3/boolean.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/data-rate.h"
#include "ns3/pointer.h"
#include "rdma-hw.h"
#include "ppp-header.h"
#include "qbb-header.h"
#include "cn-header.h"
#include "ns3/flow-id-num-tag.h"
#include "flow-stat-tag.h"
#include "tlt-tag.h"
#include "ns3/switch-node.h"
#include <climits>

#define TLT_DEBUG_ENABLE 0
#if TLT_DEBUG_ENABLE
#define TLT_DEBUG_TARGET 100
#define TLT_IS_DEBUG_TARGET(x) ((x)->m_flow_id == TLT_DEBUG_TARGET)
#define TLT_DEBUG_PRINT(x) (std::cerr << x << std::endl);
#else
#define TLT_IS_DEBUG_TARGET(x) (false)
#define TLT_DEBUG_PRINT(x)
#endif
namespace ns3{

NS_LOG_COMPONENT_DEFINE("RdmaHw");

std::unordered_map<unsigned, unsigned> acc_timeout_count;
extern struct stat_tx_ stat_tx;

TypeId RdmaHw::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::RdmaHw")
		.SetParent<Object> ()
		.AddAttribute("MinRate",
				"Minimum rate of a throttled flow",
				DataRateValue(DataRate("100Mb/s")),
				MakeDataRateAccessor(&RdmaHw::m_minRate),
				MakeDataRateChecker())
		.AddAttribute("Mtu",
				"Mtu.",
				UintegerValue(1000),
				MakeUintegerAccessor(&RdmaHw::m_mtu),
				MakeUintegerChecker<uint32_t>())
		.AddAttribute ("CcMode",
				"which mode of DCQCN is running",
				UintegerValue(0),
				MakeUintegerAccessor(&RdmaHw::m_cc_mode),
				MakeUintegerChecker<uint32_t>())
		.AddAttribute("NACK Generation Interval",
				"The NACK Generation interval",
				DoubleValue(500.0),
				MakeDoubleAccessor(&RdmaHw::m_nack_interval),
				MakeDoubleChecker<double>())
		.AddAttribute("L2ChunkSize",
				"Layer 2 chunk size. Disable chunk mode if equals to 0.",
				UintegerValue(0),
				MakeUintegerAccessor(&RdmaHw::m_chunk),
				MakeUintegerChecker<uint32_t>())
		.AddAttribute("L2AckInterval",
				"Layer 2 Ack intervals. Disable ack if equals to 0.",
				UintegerValue(0),
				MakeUintegerAccessor(&RdmaHw::m_ack_interval),
				MakeUintegerChecker<uint32_t>())
		.AddAttribute("L2BackToZero",
				"Layer 2 go back to zero transmission.",
				BooleanValue(false),
				MakeBooleanAccessor(&RdmaHw::m_backto0),
				MakeBooleanChecker())
		.AddAttribute("EwmaGain",
				"Control gain parameter which determines the level of rate decrease",
				DoubleValue(1.0 / 16),
				MakeDoubleAccessor(&RdmaHw::m_g),
				MakeDoubleChecker<double>())
		.AddAttribute ("RateOnFirstCnp",
				"the fraction of rate on first CNP",
				DoubleValue(1.0),
				MakeDoubleAccessor(&RdmaHw::m_rateOnFirstCNP),
				MakeDoubleChecker<double> ())
		.AddAttribute("ClampTargetRate",
				"Clamp target rate.",
				BooleanValue(false),
				MakeBooleanAccessor(&RdmaHw::m_EcnClampTgtRate),
				MakeBooleanChecker())
		.AddAttribute("RPTimer",
				"The rate increase timer at RP in microseconds",
				DoubleValue(1500.0),
				MakeDoubleAccessor(&RdmaHw::m_rpgTimeReset),
				MakeDoubleChecker<double>())
		.AddAttribute("RateDecreaseInterval",
				"The interval of rate decrease check",
				DoubleValue(4.0),
				MakeDoubleAccessor(&RdmaHw::m_rateDecreaseInterval),
				MakeDoubleChecker<double>())
		.AddAttribute("FastRecoveryTimes",
				"The rate increase timer at RP",
				UintegerValue(5),
				MakeUintegerAccessor(&RdmaHw::m_rpgThreshold),
				MakeUintegerChecker<uint32_t>())
		.AddAttribute("AlphaResumInterval",
				"The interval of resuming alpha",
				DoubleValue(55.0),
				MakeDoubleAccessor(&RdmaHw::m_alpha_resume_interval),
				MakeDoubleChecker<double>())
		.AddAttribute("RateAI",
				"Rate increment unit in AI period",
				DataRateValue(DataRate("5Mb/s")),
				MakeDataRateAccessor(&RdmaHw::m_rai),
				MakeDataRateChecker())
		.AddAttribute("RateHAI",
				"Rate increment unit in hyperactive AI period",
				DataRateValue(DataRate("50Mb/s")),
				MakeDataRateAccessor(&RdmaHw::m_rhai),
				MakeDataRateChecker())
		.AddAttribute("VarWin",
				"Use variable window size or not",
				BooleanValue(false),
				MakeBooleanAccessor(&RdmaHw::m_var_win),
				MakeBooleanChecker())
		.AddAttribute("FastReact",
				"Fast React to congestion feedback",
				BooleanValue(true),
				MakeBooleanAccessor(&RdmaHw::m_fast_react),
				MakeBooleanChecker())
		.AddAttribute("MiThresh",
				"Threshold of number of consecutive AI before MI",
				UintegerValue(5),
				MakeUintegerAccessor(&RdmaHw::m_miThresh),
				MakeUintegerChecker<uint32_t>())
		.AddAttribute("TargetUtil",
				"The Target Utilization of the bottleneck bandwidth, by default 95%",
				DoubleValue(0.95),
				MakeDoubleAccessor(&RdmaHw::m_targetUtil),
				MakeDoubleChecker<double>())
		.AddAttribute("UtilHigh",
				"The upper bound of Target Utilization of the bottleneck bandwidth, by default 98%",
				DoubleValue(0.98),
				MakeDoubleAccessor(&RdmaHw::m_utilHigh),
				MakeDoubleChecker<double>())
		.AddAttribute("RateBound",
				"Bound packet sending by rate, for test only",
				BooleanValue(true),
				MakeBooleanAccessor(&RdmaHw::m_rateBound),
				MakeBooleanChecker())
		.AddAttribute("MultiRate",
				"Maintain multiple rates in HPCC",
				BooleanValue(true),
				MakeBooleanAccessor(&RdmaHw::m_multipleRate),
				MakeBooleanChecker())
		.AddAttribute("SampleFeedback",
				"Whether sample feedback or not",
				BooleanValue(false),
				MakeBooleanAccessor(&RdmaHw::m_sampleFeedback),
				MakeBooleanChecker())
		.AddAttribute("TimelyAlpha",
				"Alpha of TIMELY",
				DoubleValue(0.875),
				MakeDoubleAccessor(&RdmaHw::m_tmly_alpha),
				MakeDoubleChecker<double>())
		.AddAttribute("TimelyBeta",
				"Beta of TIMELY",
				DoubleValue(0.8),
				MakeDoubleAccessor(&RdmaHw::m_tmly_beta),
				MakeDoubleChecker<double>())
		.AddAttribute("TimelyTLow",
				"TLow of TIMELY (ns)",
				UintegerValue(50000),
				MakeUintegerAccessor(&RdmaHw::m_tmly_TLow),
				MakeUintegerChecker<uint64_t>())
		.AddAttribute("TimelyTHigh",
				"THigh of TIMELY (ns)",
				UintegerValue(500000),
				MakeUintegerAccessor(&RdmaHw::m_tmly_THigh),
				MakeUintegerChecker<uint64_t>())
		.AddAttribute("TimelyMinRtt",
				"MinRtt of TIMELY (ns)",
				UintegerValue(20000),
				MakeUintegerAccessor(&RdmaHw::m_tmly_minRtt),
				MakeUintegerChecker<uint64_t>())
		.AddAttribute("DctcpRateAI",
				"DCTCP's Rate increment unit in AI period",
				DataRateValue(DataRate("1000Mb/s")),
				MakeDataRateAccessor(&RdmaHw::m_dctcp_rai),
				MakeDataRateChecker())
		.AddAttribute("IrnEnable",
				"Enable IRN",
				BooleanValue(false),
				MakeBooleanAccessor(&RdmaHw::m_irn),
				MakeBooleanChecker())
		.AddAttribute("IrnRtoLow",
			"Low RTO for IRN",
			TimeValue (MicroSeconds (454)),
			MakeTimeAccessor(&RdmaHw::m_irn_rtoLow),
			MakeTimeChecker())
		.AddAttribute("IrnRtoHigh",
			"High RTO for IRN",
			TimeValue (MicroSeconds (1350)),
			MakeTimeAccessor(&RdmaHw::m_irn_rtoHigh),
			MakeTimeChecker())
		.AddAttribute("IrnBdp",
			"BDP Limit for IRN in Bytes",
			UintegerValue(100000),
			MakeUintegerAccessor(&RdmaHw::m_irn_bdp),
			MakeUintegerChecker<uint32_t>())
    	.AddAttribute ("L2Timeout",
			"Sender's timer of waiting for the ack",
			TimeValue (MilliSeconds (4)),
			MakeTimeAccessor (&RdmaHw::m_waitAckTimeout),
			MakeTimeChecker ())
		.AddAttribute("TltEnable",
				"Enable TLT",
				BooleanValue(false),
				MakeBooleanAccessor(&RdmaHw::m_tlt),
				MakeBooleanChecker())
		.AddAttribute("TltImportantMarkingInterval",
				"Marking interval of important packet (rate-based CC only)",
				UintegerValue(96),
				MakeUintegerAccessor(&RdmaHw::m_tlt_important_marking_interval),
				MakeUintegerChecker<uint32_t>())
		;
	return tid;
}

RdmaHw::RdmaHw(){
}

void RdmaHw::PrintStat(void) {
	extern std::unordered_map<unsigned, Time> acc_pause_time;

	if(!stat_tx.stat_print) {
		printf("%.8lf\tIMP_STAT\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.txImpBytes);
		printf("%.8lf\tIMPE_STAT\t%p\t%lu\n", Simulator::Now().GetSeconds(), this,  stat_tx.txImpEBytes);
		printf("%.8lf\tUIMP_STAT\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.txUimpBytes);
		printf("%.8lf\tIMP_STAT_NIC\t%p\t%lu\n", Simulator::Now().GetSeconds(), this,  stat_tx.txImpBytesNIC);
		printf("%.8lf\tIMPE_STAT_NIC\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.txImpEBytesNIC);
		printf("%.8lf\tIMPF_STAT_NIC\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.txImpFBytesNIC);
		printf("%.8lf\tIMPEF_STAT_NIC\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.txImpEFBytesNIC);
		printf("%.8lf\tIMPC_STAT_NIC\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.txImpCBytesNIC);
		printf("%.8lf\tUIMP_STAT_NIC\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.txUimpBytesNIC);

		printf("%.8lf\tIMP_STAT_NIC_PL\t%p\t%lu\n", Simulator::Now().GetSeconds(), this,  stat_tx.txImpBytesNIC_PL);
		printf("%.8lf\tIMP_STAT_NIC_PLE\t%p\t%lu\n", Simulator::Now().GetSeconds(), this,  stat_tx.txImpBytesNIC_PLE);
		printf("%.8lf\tIMP_STAT_NIC_PLR\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.txImpBytesNIC_PLR);
		printf("%.8lf\tIMP_STAT_NIC_CNP\t%p\t%lu\n", Simulator::Now().GetSeconds(), this,  stat_tx.txImpBytesNIC_CNP);
		printf("%.8lf\tIMP_STAT_NIC_ACK\t%p\t%lu\n", Simulator::Now().GetSeconds(), this,  stat_tx.txImpBytesNIC_ACK);
		printf("%.8lf\tIMP_STAT_NIC_NACK\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.txImpBytesNIC_NACK);

		printf("%.8lf\tTLT_DROP\t%p\t%lu\n", Simulator::Now().GetSeconds(), this,  stat_tx.txTltDropBytes);
		printf("%.8lf\tPAUSE\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.PauseSendCnt);
		printf("%.8lf\tL2_RTO\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.RetxTimeoutCnt);
		printf("%.8lf\tIMP_DROP_BYTES\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.importantDropBytes);
		printf("%.8lf\tIMP_DROP_CNT\t%p\t%lu\n", Simulator::Now().GetSeconds(), this, stat_tx.importantDropCnt);

		Time totalPauseDuration;

		for (auto it = acc_pause_time.begin(); it != acc_pause_time.end(); ++it) {
			totalPauseDuration += it->second;
		}

		printf("%.8lf\tPFC_TIME_TOTAL\t%p\t%.8lf\n", Simulator::Now().GetSeconds(), this, totalPauseDuration.GetSeconds());

		stat_tx.stat_print = true;
	}
}

void RdmaHw::SetNode(Ptr<Node> node){
	m_node = node;
}
void RdmaHw::Setup(QpCompleteCallback cb){
	for (uint32_t i = 0; i < m_nic.size(); i++){
		Ptr<QbbNetDevice> dev = m_nic[i].dev;
		if (dev == NULL)
			continue;
		// share data with NIC
		dev->m_rdmaEQ->m_qpGrp = m_nic[i].qpGrp;
		// setup callback
		dev->m_rdmaReceiveCb = MakeCallback(&RdmaHw::Receive, this);
		dev->m_rdmaLinkDownCb = MakeCallback(&RdmaHw::SetLinkDown, this);
		dev->m_rdmaPktSent = MakeCallback(&RdmaHw::PktSent, this);
		// config NIC
		dev->m_rdmaEQ->m_mtu = m_mtu;
		dev->m_rdmaEQ->m_rdmaGetNxtPkt = MakeCallback(&RdmaHw::GetNxtPacket, this);
	}
	// setup qp complete callback
	m_qpCompleteCallback = cb;
}

uint32_t RdmaHw::GetNicIdxOfQp(Ptr<RdmaQueuePair> qp){
	auto &v = m_rtTable[qp->dip.Get()];
	if (v.size() > 0){
		return v[qp->GetHash() % v.size()];
	}else{
		NS_ASSERT_MSG(false, "We assume at least one NIC is alive");
	}
}
uint64_t RdmaHw::GetQpKey(uint16_t sport, uint16_t pg){
	return ((uint64_t)sport << 16) | (uint64_t)pg;
}
Ptr<RdmaQueuePair> RdmaHw::GetQp(uint16_t sport, uint16_t pg){
	uint64_t key = GetQpKey(sport, pg);
	auto it = m_qpMap.find(key);
	if (it != m_qpMap.end())
		return it->second;
	return NULL;
}
void RdmaHw::AddQueuePair(uint64_t size, uint16_t pg, Ipv4Address sip, Ipv4Address dip, uint16_t sport, uint16_t dport, uint32_t win, uint64_t baseRtt, int32_t flow_id){
	// create qp
	Ptr<RdmaQueuePair> qp = CreateObject<RdmaQueuePair>(pg, sip, dip, sport, dport);
	qp->SetSize(size);
	qp->SetWin(win);
	qp->SetBaseRtt(baseRtt);
	qp->SetVarWin(m_var_win);
	qp->SetFlowId(flow_id);
	qp->SetTimeout(m_waitAckTimeout);

	if (m_irn) {
		qp->irn.m_enabled = m_irn;
		qp->irn.m_bdp = m_irn_bdp;
		qp->irn.m_rtoLow = m_irn_rtoLow;
		qp->irn.m_rtoHigh = m_irn_rtoHigh;
	}

	qp->tlt.m_cc_type = GetCcType();
	if (m_tlt) {
		qp->tlt.m_enabled = m_tlt;
		qp->tlt.m_sendState = TLT_STATE_IMPORTANT;
		qp->tlt.m_tlt_unimportant_pkts_current_round = CreateObject<SelectivePacketQueue>();
		qp->tlt.m_tlt_unimportant_pkts_prev_round = CreateObject<SelectivePacketQueue>();
		NS_ASSERT(qp->tlt.m_tlt_unimportant_pkts_current_round);
		NS_ASSERT(qp->tlt.m_tlt_unimportant_pkts_prev_round);
	}

	// add qp
	uint32_t nic_idx = GetNicIdxOfQp(qp);
	m_nic[nic_idx].qpGrp->AddQp(qp);
	uint64_t key = GetQpKey(sport, pg);
	m_qpMap[key] = qp;

	// set init variables
	DataRate m_bps = m_nic[nic_idx].dev->GetDataRate();
	qp->m_rate = m_bps;
	qp->m_max_rate = m_bps;
	if (m_cc_mode == 1){
		qp->mlx.m_targetRate = m_bps;
	}else if (m_cc_mode == 3){
		qp->hp.m_curRate = m_bps;
		if (m_multipleRate){
			for (uint32_t i = 0; i < IntHeader::maxHop; i++)
				qp->hp.hopState[i].Rc = m_bps;
		}
	}else if (m_cc_mode == 7){
		qp->tmly.m_curRate = m_bps;
	}

	// Notify Nic
	m_nic[nic_idx].dev->NewQp(qp);
}

Ptr<RdmaRxQueuePair> RdmaHw::GetRxQp(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint16_t pg, bool create){
	uint64_t key = ((uint64_t)dip << 32) | ((uint64_t)pg << 16) | (uint64_t)dport;
	auto it = m_rxQpMap.find(key);
	if (it != m_rxQpMap.end())
		return it->second;
	if (create){
		// create new rx qp
		Ptr<RdmaRxQueuePair> q = CreateObject<RdmaRxQueuePair>();
		// init the qp
		q->sip = sip;
		q->dip = dip;
		q->sport = sport;
		q->dport = dport;
		q->m_ecn_source.qIndex = pg;
		q->m_flow_id = -1; // unknown
		q->m_tlt_recvState = TLT_STATE_IDLE;
		// store in map
		m_rxQpMap[key] = q;
		return q;
	}
	return NULL;
}
uint32_t RdmaHw::GetNicIdxOfRxQp(Ptr<RdmaRxQueuePair> q){
	auto &v = m_rtTable[q->dip];
	if (v.size() > 0){
		return v[q->GetHash() % v.size()];
	}else{
		NS_ASSERT_MSG(false, "We assume at least one NIC is alive");
	}
}

#if TLT_DEBUG_ENABLE

void tlt_debug_print(Ptr<RdmaQueuePair> qp, Ptr<RdmaRxQueuePair> rxQp, uint32_t seq, TltTag &tlt, std::string msg, std::string additional) {
	
	std::string tagtype;
	switch(tlt.GetType()) {
	case TltTag::PACKET_IMPORTANT:
		tagtype = "Imp  ";
		break;
	case TltTag::PACKET_IMPORTANT_ECHO:
		tagtype = "ImpE ";
		break;
	case TltTag::PACKET_IMPORTANT_FORCE:
		tagtype = "ImpF ";
		break;
	case TltTag::PACKET_IMPORTANT_ECHO_FORCE:
		tagtype = "ImpFE";
		break;
	case TltTag::PACKET_NOT_IMPORTANT:
		tagtype = "Uimp ";
		break;
	case TltTag::PACKET_IMPORTANT_CONTROL:
		tagtype = "ImpC ";
		break;
	case TltTag::PACKET_IMPORTANT_FAST_RETRANS:
		tagtype = "ImpfR";
		break;
	default:
		tagtype = "Unknown";
		break;
	}

	char mss[1024]; sprintf(mss, "%.8lf", Simulator::Now().GetSeconds() * 1000.);
	TLT_DEBUG_PRINT("[" <<  std::string(mss) <<"] Flow " << (qp ? (qp->m_flow_id) : rxQp->m_flow_id) << " : " << msg << " " << tagtype << " " << seq << additional);
}
inline void tlt_debug_recv_print(Ptr<RdmaRxQueuePair> rxQp, uint32_t seq, TltTag &tlt, std::string additional) {
	if(TLT_IS_DEBUG_TARGET(rxQp))
		tlt_debug_print(nullptr, rxQp, seq, tlt, "Recv UDP                                     ", additional);
}
inline void tlt_debug_recv_print(Ptr<RdmaQueuePair> qp, uint32_t seq, TltTag &tlt, std::string additional) {
	if(TLT_IS_DEBUG_TARGET(qp))
		tlt_debug_print(qp, nullptr, seq, tlt, "Recv ACK             ", additional);
}
inline void tlt_debug_send_print(Ptr<RdmaRxQueuePair> rxQp, uint32_t seq, TltTag &tlt, std::string additional) {
	if(TLT_IS_DEBUG_TARGET(rxQp))
		tlt_debug_print(nullptr, rxQp, seq, tlt, "Send ACK                         ", additional);
}
inline void tlt_debug_send_print(Ptr<RdmaQueuePair> qp, uint32_t seq, TltTag &tlt, std::string additional) {
	if(TLT_IS_DEBUG_TARGET(qp))
		tlt_debug_print(qp, nullptr, seq, tlt, "Send UDP ", additional);
}
#else
inline void tlt_debug_recv_print(Ptr<RdmaRxQueuePair> rxQp, uint32_t seq, TltTag &tlt, std::string additional) {}
inline void tlt_debug_recv_print(Ptr<RdmaQueuePair> qp, uint32_t seq, TltTag &tlt, std::string additional) {}
inline void tlt_debug_send_print(Ptr<RdmaRxQueuePair> rxQp, uint32_t seq, TltTag &tlt, std::string additional) {}
inline void tlt_debug_send_print(Ptr<RdmaQueuePair> qp, uint32_t seq, TltTag &tlt, std::string additional) {}
#endif


int RdmaHw::ReceiveUdp(Ptr<Packet> p, CustomHeader &ch){
	uint8_t ecnbits = ch.GetIpv4EcnBits();

	uint32_t payload_size = p->GetSize() - ch.GetSerializedSize();

	// TODO find corresponding rx queue pair
	Ptr<RdmaRxQueuePair> rxQp = GetRxQp(ch.dip, ch.sip, ch.udp.dport, ch.udp.sport, ch.udp.pg, true);
	if (ecnbits != 0){
		rxQp->m_ecn_source.ecnbits |= ecnbits;
		rxQp->m_ecn_source.qfb++;
	}
	rxQp->m_ecn_source.total++;
	rxQp->m_milestone_rx = m_ack_interval;

	if (rxQp->m_flow_id < 0) {
		FlowIDNUMTag fit;
		if (p->PeekPacketTag(fit)) {
			rxQp->m_flow_id = fit.GetId();
		}
	}

	// if (Simulator::Now().GetSeconds() * 1000 >= 20.52949 && rxQp->m_flow_id == TLT_DEBUG_TARGET) {
	// 	std::cerr << "Reached debug point." << std::endl;
	// }
	if (m_tlt) {
		TltTag tlt;
		if (p->PeekPacketTag(tlt)) {
			tlt_debug_recv_print(rxQp, ch.udp.seq, tlt, std::string());
			if (IsWindowBasedCC()) {
				if (tlt.GetType() == TltTag::PACKET_IMPORTANT)
					rxQp->m_tlt_recvState = TLT_STATE_IMPORTANT;
				else if (tlt.GetType() == TltTag::PACKET_IMPORTANT_FORCE)
					rxQp->m_tlt_recvState = TLT_STATE_IMPORTANT_FORCE;

				if (payload_size == 0 && (tlt.GetType() == TltTag::PACKET_IMPORTANT || tlt.GetType() == TltTag::PACKET_IMPORTANT_FORCE)) {
					// TLT FIN : do not deliver to App. layer
					char mss[1024]; sprintf(mss, "%.8lf", Simulator::Now().GetSeconds() * 1000.);
					if (TLT_IS_DEBUG_TARGET(rxQp))
						TLT_DEBUG_PRINT("[" <<  std::string(mss) <<"] Flow " << (rxQp->m_flow_id) << " : Recv FIN");
					return 1;
				}
			}
		} else {
			std::cerr << "Warning: Cannot find TLT tag" << std::endl;
		}
	}
	
	int x = ReceiverCheckSeq(ch.udp.seq, rxQp, payload_size);
	// {
	// 	FlowIDNUMTag fit;
	// 	if (p->PeekPacketTag(fit)) {
	// 		if (fit.GetId() == 15 ) {
	// 			std::cout << "FLOW: Recv " << ch.udp.seq << ", x=" << x << ", ack=" << rxQp->ReceiverNextExpectedSeq << ", sack=" << rxQp->m_irn_sack_ << std::endl;
	// 		}
	// 	}
	// }
	if (x == 1 || x == 2 || x == 6 || (x == 4 && m_tlt && rxQp->m_tlt_recvState != TLT_STATE_IDLE)){ //generate ACK or NACK
		qbbHeader seqh;
		seqh.SetSeq(rxQp->ReceiverNextExpectedSeq);
		seqh.SetPG(ch.udp.pg);
		seqh.SetSport(ch.udp.dport);
		seqh.SetDport(ch.udp.sport);
		seqh.SetIntHeader(ch.udp.ih);

		if (m_irn) {
			if (x == 2) {
				seqh.SetIrnNack(ch.udp.seq);
				seqh.SetIrnNackSize(payload_size);
			} else {
				seqh.SetIrnNack(0); // NACK without ackSyndrome (ACK) in loss recovery mode
				seqh.SetIrnNackSize(0);
			}
		}

		if (ecnbits)
			seqh.SetCnp();

		Ptr<Packet> newp = Create<Packet>(std::max(60-14-20-(int)seqh.GetSerializedSize(), 0));
		newp->AddHeader(seqh);

		Ipv4Header head;	// Prepare IPv4 header
		head.SetDestination(Ipv4Address(ch.sip));
		head.SetSource(Ipv4Address(ch.dip));
		head.SetProtocol(x == 1 ? 0xFC : 0xFD); //ack=0xFC nack=0xFD
		head.SetTtl(64);
		head.SetPayloadSize(newp->GetSize());
		head.SetIdentification(rxQp->m_ipid++);

		{
			FlowIDNUMTag fit;
			if (p->PeekPacketTag(fit)) {
				newp->AddPacketTag(fit);
			}
		}

		newp->AddHeader(head);
		AddHeader(newp, 0x800);	// Attach PPP header

		if (m_tlt) {
			TltTag tlt;
			if (IsWindowBasedCC()) {
				if (rxQp->m_tlt_recvState == TLT_STATE_IMPORTANT)
					tlt.SetType(TltTag::PACKET_IMPORTANT_ECHO);
				else if (rxQp->m_tlt_recvState == TLT_STATE_IMPORTANT_FORCE)
					tlt.SetType(TltTag::PACKET_IMPORTANT_ECHO_FORCE);
				else
					tlt.SetType(TltTag::PACKET_IMPORTANT_CONTROL);
				rxQp->m_tlt_recvState = TLT_STATE_IDLE;
				tlt.SetControlType(TltTag::PACKET_NACK);
				newp->AddPacketTag(tlt);

				#if TLT_DEBUG_ENABLE
				char tbuf[128] = { 0, };
				if (x == 2)
					sprintf(tbuf, "(NACK %u-%u)", ch.udp.seq, ch.udp.seq + payload_size);
				tlt_debug_send_print(rxQp, rxQp->ReceiverNextExpectedSeq, tlt, std::string(tbuf));
				#endif
			} else {
				tlt.SetType(TltTag::PACKET_IMPORTANT_CONTROL);
				tlt.SetControlType(x == 1 ? TltTag::PACKET_ACK : TltTag::PACKET_NACK);
				newp->AddPacketTag(tlt);
				tlt_debug_send_print(rxQp, rxQp->ReceiverNextExpectedSeq, tlt, "");
			}
		}

		// send
		uint32_t nic_idx = GetNicIdxOfRxQp(rxQp);
		m_nic[nic_idx].dev->RdmaEnqueueHighPrioQ(newp);
		m_nic[nic_idx].dev->TriggerTransmit();
	}
	return 0;
}

int RdmaHw::ReceiveCnp(Ptr<Packet> p, CustomHeader &ch){
	// QCN on NIC
	// This is a Congestion signal
	// Then, extract data from the congestion packet.
	// We assume, without verify, the packet is destinated to me
	uint32_t qIndex = ch.cnp.qIndex;
	if (qIndex == 1){		//DCTCP
		std::cout << "TCP--ignore\n";
		return 0;
	}
	uint16_t udpport = ch.cnp.fid; // corresponds to the sport
	uint8_t ecnbits = ch.cnp.ecnBits;
	uint16_t qfb = ch.cnp.qfb;
	uint16_t total = ch.cnp.total;

	uint32_t i;
	// get qp
	Ptr<RdmaQueuePair> qp = GetQp(udpport, qIndex);
	if (qp == NULL)
		std::cout << "ERROR: QCN NIC cannot find the flow\n";
	// get nic
	uint32_t nic_idx = GetNicIdxOfQp(qp);
	Ptr<QbbNetDevice> dev = m_nic[nic_idx].dev;

	if (qp->m_rate == 0)			//lazy initialization	
	{
		qp->m_rate = dev->GetDataRate();
		if (m_cc_mode == 1){
			qp->mlx.m_targetRate = dev->GetDataRate();
		}else if (m_cc_mode == 3){
			qp->hp.m_curRate = dev->GetDataRate();
			if (m_multipleRate){
				for (uint32_t i = 0; i < IntHeader::maxHop; i++)
					qp->hp.hopState[i].Rc = dev->GetDataRate();
			}
		}else if (m_cc_mode == 7){
			qp->tmly.m_curRate = dev->GetDataRate();
		}
	}
	return 0;
}

int RdmaHw::ReceiveAck(Ptr<Packet> p, CustomHeader &ch){
	uint16_t qIndex = ch.ack.pg;
	uint16_t port = ch.ack.dport;
	uint32_t seq = ch.ack.seq;
	uint8_t cnp = (ch.ack.flags >> qbbHeader::FLAG_CNP) & 1;
	int i;
	Ptr<RdmaQueuePair> qp = GetQp(port, qIndex);
	if (qp == NULL){
		std::cout << "ERROR: " << "node:" << m_node->GetId() << ' ' << (ch.l3Prot == 0xFC ? "ACK" : "NACK") << " NIC cannot find the flow\n";
		return 0;
	}

	uint32_t nic_idx = GetNicIdxOfQp(qp);
	Ptr<QbbNetDevice> dev = m_nic[nic_idx].dev;

	TltTag tlt;
	if (m_tlt)
	{
		if (p->PeekPacketTag(tlt)) {
			tlt_debug_recv_print(qp, seq, tlt, std::string());
			if (IsWindowBasedCC()) {
				if (tlt.GetType() == TltTag::PACKET_IMPORTANT_ECHO || tlt.GetType() == TltTag::PACKET_IMPORTANT_ECHO_FORCE) {
					if (qp->tlt.m_sendState == TLT_STATE_IMPORTANT || qp->tlt.m_sendState == TLT_STATE_IMPORTANT_FORCE) {
						std::cout << "WARN : Already pending important here... two important echoes?" << std::endl;
					}
					if (qp->tlt.m_highestImportantAck < seq)
						qp->tlt.m_highestImportantAck = seq;
					qp->tlt.m_sendState = TLT_STATE_IMPORTANT;
					if (tlt.GetType() == TltTag::PACKET_IMPORTANT_ECHO_FORCE) {
						// if (seq < qp->snd_una) {
						// 	// do not deliver to CC layer
						// 	TLT_DEBUG_PRINT("Flow " << qp->m_flow_id << " : -> Not delivering because seq=" << seq << ", snd_una=" << qp->snd_una);
						// 	return 0;
						// }
					}
				}
			}
		} else {
			std::cerr << "Warning: Cannot find TLT tag" << std::endl;
		}

		// if (Simulator::Now().GetSeconds() * 1000 >= 20.4073 && qp->m_flow_id == TLT_DEBUG_TARGET) {  //22.16406
		// 	std::cerr << "Reached debug point." << std::endl;
		// }

		if (IsWindowBasedCC()) {
			qp->tlt.m_tlt_unimportant_pkts.discardUpTo(SequenceNumber32(seq));
			qp->tlt.m_tlt_unimportant_pkts_prev_round->discardUpTo(SequenceNumber32(seq));
			qp->tlt.m_tlt_unimportant_pkts_current_round->discardUpTo(SequenceNumber32(seq));
		}
	}

	if (m_ack_interval == 0)
		std::cout << "ERROR: shouldn't receive ack\n";
	else {
		if (!m_backto0){
			qp->Acknowledge(seq);
		}else {
			uint32_t goback_seq = seq / m_chunk * m_chunk;
			qp->Acknowledge(goback_seq);
		}
		if (qp->irn.m_enabled) {
			// handle NACK
			NS_ASSERT(ch.l3Prot == 0xFD);

			//for bdp-fc calculation update m_irn_maxAck
			if (seq > qp->irn.m_highest_ack)
				qp->irn.m_highest_ack = seq;
			

			if (ch.ack.irnNackSize != 0) {
				// ch.ack.irnNack contains the seq triggered this NACK
				qp->irn.m_sack.sack(ch.ack.irnNack, ch.ack.irnNackSize);
			}

			if (qp->tlt.m_enabled && IsWindowBasedCC() && ch.ack.irnNackSize > 0) {
				SelectivePacketQueue::SackList list;
				list.push_back(std::pair<SequenceNumber32, SequenceNumber32>(SequenceNumber32(ch.ack.irnNack), SequenceNumber32(ch.ack.irnNack+ch.ack.irnNackSize)));
				qp->tlt.m_tlt_unimportant_pkts.updateSack(list);
				qp->tlt.m_tlt_unimportant_pkts_prev_round->updateSack(list);
				qp->tlt.m_tlt_unimportant_pkts_current_round->updateSack(list);
			}

			{
				uint32_t sack_seq, sack_len;
				if (qp->irn.m_sack.peekFrontBlock(&sack_seq, &sack_len)) {
					if (qp->snd_una == sack_seq) {
						qp->snd_una += sack_len;
					}
				}
			}

			qp->irn.m_sack.discardUpTo(qp->snd_una);
			
			if (qp->snd_nxt < qp->snd_una) {
				qp->snd_nxt = qp->snd_una;
			}
			//if (qp->irn.m_sack.IsEmpty())  { // 
			if (qp->irn.m_recovery && qp->snd_una >= qp->irn.m_recovery_seq) {
				qp->irn.m_recovery = false;
			}

			if (qp->tlt.m_enabled && IsWindowBasedCC()) {
				qp->tlt.m_tlt_unimportant_pkts.discardUpTo(SequenceNumber32(qp->snd_una));
			}
			
			// {
			// 	FlowIDNUMTag fit;
			// 	if (p->PeekPacketTag(fit)) {
			// 		if (fit.GetId() == 15 ) {
			// 			std::cout << "FLOW: Nack " << ch.udp.seq << ", (" << ch.ack.irnNack << "), snd_una=" << qp->snd_una << ", snd_nxt=" << qp->snd_nxt << ", sack=" << qp->irn.m_sack << std::endl;
			// 		}
			// 	}
			// }

		} else {
			if (qp->snd_nxt < qp->snd_una) {
				qp->snd_nxt = qp->snd_una;
			}
		}
		if (qp->IsFinished()){
			if(qp->tlt.m_enabled && IsWindowBasedCC()) {
				if (!qp->tlt.m_sent_fin && qp->tlt.m_sendState != TLT_STATE_IDLE) {
					// TLT : Tail loss (packet transmitted after last Imp packet) might incur timeout
					GenerateTltFin(qp);
					qp->tlt.m_sent_fin = true;
					QpComplete(qp);
				}
				else
				{
					QpComplete(qp);
					qp->tlt.m_sent_fin = true;
				}
			} else {
				QpComplete(qp);
			}
		}
	}

	/** 
	 * IB Spec Vol. 1 o9-85
	 * The requester need not separately time each request launched into the
	 * fabric, but instead simply begins the timer whenever it is expecting a response.
	 * Once started, the timer is restarted each time an acknowledge
	 * packet is received as long as there are outstanding expected responses.
	 * The timer does not detect the loss of a particular expected acknowledge
	 * packet, but rather simply detects the persistent absence of response
	 * packets.
	 * */
	if (!qp->IsFinished() && qp->GetOnTheFly() > 0) {
		if (qp->m_retransmit.IsRunning())
			qp->m_retransmit.Cancel();
		qp->m_retransmit = Simulator::Schedule(qp->GetRto(m_mtu), &RdmaHw::HandleTimeout, this, qp, qp->GetRto(m_mtu));
	}
	
	if (m_irn) {
		if (ch.ack.irnNackSize != 0) {
			if (!qp->irn.m_recovery) {
				qp->irn.m_recovery_seq = qp->snd_nxt;
				RecoverQueue(qp);
				qp->irn.m_recovery = true;
			}
		} else {
			if (qp->irn.m_recovery) {
				qp->irn.m_recovery = false;
			}
		}
			
	} else if (ch.l3Prot == 0xFD) // NACK
		RecoverQueue(qp);

	// handle cnp
	if (cnp){
		if (m_cc_mode == 1){ // mlx version
			cnp_received_mlx(qp);
		} 
	}

	if (m_cc_mode == 3){
		HandleAckHp(qp, p, ch);
	}else if (m_cc_mode == 7){
		HandleAckTimely(qp, p, ch);
	}else if (m_cc_mode == 8){
		HandleAckDctcp(qp, p, ch);
	}
	// ACK may advance the on-the-fly window, allowing more packets to send
	dev->TriggerTransmit();
	

	// Must be done after DoForwardUp(TriggerTransmit)
	if (qp->tlt.m_enabled && IsWindowBasedCC()) {
#if 0
		bool cond_window = !qp->IsWinBound() && (!qp->irn.m_enabled || qp->CanIrnTransmit(m_mtu));
		// checking if qp->tlt.m_sendState == TLT_STATE_IMPORTANT is not correct.
		// queued important packet might be send next time..
		// TODO: think about this..
		if (qp->tlt.m_sendState == TLT_STATE_IMPORTANT && !cond_window && !qp->IsFinished()) {
			// TLT force transmission required
			qp->tlt.m_sendUnit = m_mtu; // Reset to MTU(MSS)
			bool tlt_success = forceSendTLT(qp, nullptr);
			// TODO: Fill up here
		}
#endif
		if (tlt.GetType() == TltTag::PACKET_IMPORTANT_ECHO || tlt.GetType() == TltTag::PACKET_IMPORTANT_ECHO_FORCE) {
			qp->tlt.m_tlt_unimportant_pkts_prev_round = qp->tlt.m_tlt_unimportant_pkts_current_round;
			qp->tlt.m_tlt_unimportant_pkts_current_round = CreateObject<SelectivePacketQueue>();
			NS_ASSERT(qp->tlt.m_tlt_unimportant_pkts_prev_round);
			NS_ASSERT(qp->tlt.m_tlt_unimportant_pkts_current_round);
		}
	}
	return 0;
}

void RdmaHw::GenerateTltFin(Ptr<RdmaQueuePair> qp) { //generate ACK or NACK
	Ptr<Packet> p = Create<Packet> (0);
	// add SeqTsHeader
	SeqTsHeader seqTs;
	seqTs.SetSeq (qp->m_size);
	seqTs.SetPG (qp->m_pg);
	p->AddHeader (seqTs);
	// add udp header
	UdpHeader udpHeader;
	udpHeader.SetDestinationPort (qp->dport);
	udpHeader.SetSourcePort (qp->sport);
	p->AddHeader (udpHeader);
	// add ipv4 header
	Ipv4Header ipHeader;
	ipHeader.SetSource (qp->sip);
	ipHeader.SetDestination (qp->dip);
	ipHeader.SetProtocol (0x11);
	ipHeader.SetPayloadSize (p->GetSize());
	ipHeader.SetTtl (64);
	ipHeader.SetTos (0);
	ipHeader.SetIdentification (qp->m_ipid);
	p->AddHeader(ipHeader);
	// add ppp header
	PppHeader ppp;
	ppp.SetProtocol (0x0021); // EtherToPpp(0x800), see point-to-point-net-device.cc
	p->AddHeader (ppp);

	// attach Stat Tag 
	{
		FlowIDNUMTag fint;
		if (!p->PeekPacketTag(fint)) {
			fint.SetId(qp->m_flow_id);
			fint.SetFlowSize(qp->m_size);
			p->AddPacketTag(fint);
		}
		FlowStatTag fst;
		uint64_t size = qp->m_size;
		if (!p->PeekPacketTag(fst))
		{
			fst.SetType(FlowStatTag::FLOW_FIN);
			fst.setInitiatedTime(Simulator::Now().GetSeconds());
			p->AddPacketTag(fst);
		}
	}

	TltTag tlt;
	tlt.SetType(TltTag::PACKET_IMPORTANT);
	tlt.SetControlType(TltTag::PACKET_PAYLOAD_EOF);
	p->AddPacketTag(tlt);
	
	char mss[1024]; sprintf(mss, "%.8lf", Simulator::Now().GetSeconds() * 1000.);
	if (TLT_IS_DEBUG_TARGET(qp))
		TLT_DEBUG_PRINT("[" <<  std::string(mss) <<"] Flow " << (qp->m_flow_id) << " : Send FIN");
	// send
	uint32_t nic_idx = GetNicIdxOfQp(qp);
	m_nic[nic_idx].dev->RdmaEnqueueHighPrioQ(p);
	m_nic[nic_idx].dev->TriggerTransmit();
}

bool RdmaHw::forceSendTLT(Ptr<RdmaQueuePair> qp, int *pSize) {
	if (!qp->tlt.m_enabled)
		return false;
	if (qp->IsFinished())
		return false;
	if (!IsWindowBasedCC())
		return false;	//no force transmission on rate-based CC

	if (qp->tlt.m_tlt_unimportant_pkts.size() == 0) {
		std::cerr << "WARNING : No Data to Force Retransmit : Must not reach here!! SocketId=" << qp->m_flow_id << std::endl;
		abort();
    	return false;
	}
	
	NS_ASSERT(qp->tlt.m_tlt_unimportant_pkts.size() > 0);
	// first packet as unimportant

	auto targetPair = qp->tlt.m_tlt_unimportant_pkts.peek(m_mtu);
	SequenceNumber32 targetSeq = targetPair.first;
	uint32_t targetSz = targetPair.second;
	
	if (targetSeq >= SequenceNumber32(qp->m_size) || !targetSz) {
		NS_LOG_INFO("No Data to Force Retransmit");
		return false;
	}

	uint32_t nPacketsSent = 0;
	uint32_t availSz = qp->m_size - targetSeq.GetValue();
	availSz = std::min(availSz, targetSz);

	uint32_t actualSz = availSz;

	bool is_loss_probable = !(qp->tlt.m_tlt_unimportant_pkts_prev_round->isEmpty() && qp->tlt.m_tlt_unimportant_pkts_prev_round->isDirty());
	uint32_t tlt_su = is_loss_probable ? m_mtu : 1;
	actualSz = std::min(tlt_su, availSz);
	
	if(!qp->tlt.m_tlt_unimportant_pkts_prev_round->isEmpty()) {
		auto ret = qp->tlt.m_tlt_unimportant_pkts_prev_round->pop(actualSz);
		targetSeq = ret.first;
		actualSz = ret.second;
		NS_ASSERT(targetSeq >= SequenceNumber32(qp->snd_una));
		qp->tlt.m_tlt_unimportant_pkts.discard(targetSeq, actualSz);
		qp->tlt.m_tlt_unimportant_pkts_current_round->discard(targetSeq, actualSz);
	} else {
		auto ret = qp->tlt.m_tlt_unimportant_pkts.pop(actualSz); // assume queue not modified between peek and pop
		NS_ABORT_UNLESS(targetSeq == ret.first);
		NS_ABORT_UNLESS(actualSz == ret.second);
		qp->tlt.m_tlt_unimportant_pkts_prev_round->discard(targetSeq, actualSz);
		qp->tlt.m_tlt_unimportant_pkts_current_round->discard(targetSeq, actualSz);
	}

	NS_ASSERT(qp->tlt.m_sendState == TLT_STATE_IMPORTANT);

	if (actualSz) {
		qp->tlt.m_forcetx_queue.push_back(std::pair<uint32_t, uint32_t>(targetSeq.GetValue(), actualSz));
		qp->tlt.m_sendState = TLT_STATE_SCHEDULED;
		if(pSize)
			*pSize = actualSz;
		qp->tlt.stat_uimp_forcegen += actualSz;
		qp->tlt.stat_uimp_forcegen_cnt++;
		nPacketsSent++;
	}

	return (nPacketsSent > 0);
}

int RdmaHw::Receive(Ptr<Packet> p, CustomHeader &ch){
	if (ch.l3Prot == 0x11){ // UDP
		return ReceiveUdp(p, ch);
	}else if (ch.l3Prot == 0xFF){ // CNP
		return ReceiveCnp(p, ch);
	}else if (ch.l3Prot == 0xFD){ // NACK
		return ReceiveAck(p, ch);
	}else if (ch.l3Prot == 0xFC){ // ACK
		return ReceiveAck(p, ch);
	}
	return 0;
}

int RdmaHw::ReceiverCheckSeq(uint32_t seq, Ptr<RdmaRxQueuePair> q, uint32_t size){
	uint32_t expected = q->ReceiverNextExpectedSeq;
	if (seq == expected || (seq < expected && seq + size >= expected)){
		if (m_irn) {
			if (q->m_milestone_rx < seq + size)
				q->m_milestone_rx = seq + size;
			q->ReceiverNextExpectedSeq += size - (expected - seq); 
			{
				uint32_t sack_seq, sack_len;
				if (q->m_irn_sack_.peekFrontBlock(&sack_seq, &sack_len)) {
					if (sack_seq <= q->ReceiverNextExpectedSeq)
						q->ReceiverNextExpectedSeq += (sack_len - (q->ReceiverNextExpectedSeq-sack_seq));
				}
			}
			size_t progress = q->m_irn_sack_.discardUpTo(q->ReceiverNextExpectedSeq);
			if (q->m_irn_sack_.IsEmpty()) {
				return 6; // This generates NACK, but actually functions as an ACK (indicates all packet has been received)
			} else {
				//should we put nack timer here
				return 2; // Still in loss recovery mode of IRN
			}
			return 0; // should not reach here
		}

		q->ReceiverNextExpectedSeq += size - (expected - seq);
		if (q->ReceiverNextExpectedSeq >= q->m_milestone_rx){
			q->m_milestone_rx += m_ack_interval;
			return 1; //Generate ACK
		}else if (q->ReceiverNextExpectedSeq % m_chunk == 0){
			return 1;
		}else {
			return 5;
		}
	} else if (seq > expected) {
		// Generate NACK
		if (m_irn) {
			if (q->m_milestone_rx < seq + size)
				q->m_milestone_rx = seq + size;
			
			//if seq is already nacked, check for nacktimer
			if (q->m_irn_sack_.blockExists(seq, size) && Simulator::Now() < q->m_nackTimer) {
				return 4; // don't need to send nack yet
			}
			q->m_nackTimer = Simulator::Now() + MicroSeconds(m_nack_interval);
			q->m_irn_sack_.sack(seq, size);
			NS_ASSERT(q->m_irn_sack_.discardUpTo(expected) == 0); // SACK blocks must be larger than expected
			return 2;
		}
		if (Simulator::Now() >= q->m_nackTimer || q->m_lastNACK != expected){
			q->m_nackTimer = Simulator::Now() + MicroSeconds(m_nack_interval);
			q->m_lastNACK = expected;
			if (m_backto0){
				q->ReceiverNextExpectedSeq = q->ReceiverNextExpectedSeq / m_chunk*m_chunk;
			}
			return 2;
		}else
			return 4;
	}else {
		// Duplicate. 
		if (m_irn) {
			// if (q->ReceiverNextExpectedSeq - 1 == q->m_milestone_rx) {
			// 	return 6; // This generates NACK, but actually functions as an ACK (indicates all packet has been received)
			// }
			if (q->m_irn_sack_.IsEmpty()) {
				return 6; // This generates NACK, but actually functions as an ACK (indicates all packet has been received)
			} else {
				//should we put nack timer here
				return 2; // Still in loss recovery mode of IRN
			}
		}
		// Duplicate. 
		return 1; // According to IB Spec C9-110
		/**
		 * IB Spec C9-110
		 * A responder shall respond to all duplicate requests in PSN order;
		 * i.e. the request with the (logically) earliest PSN shall be executed first. If,
		 * while responding to a new or duplicate request, a duplicate request is received
		 * with a logically earlier PSN, the responder shall cease responding
		 * to the original request and shall begin responding to the duplicate request
		 * with the logically earlier PSN.
		 */
	}
}
void RdmaHw::AddHeader (Ptr<Packet> p, uint16_t protocolNumber){
	PppHeader ppp;
	ppp.SetProtocol (EtherToPpp (protocolNumber));
	p->AddHeader (ppp);
}
uint16_t RdmaHw::EtherToPpp (uint16_t proto){
	switch(proto){
		case 0x0800: return 0x0021;   //IPv4
		case 0x86DD: return 0x0057;   //IPv6
		default: NS_ASSERT_MSG (false, "PPP Protocol number not defined!");
	}
	return 0;
}

void RdmaHw::RecoverQueue(Ptr<RdmaQueuePair> qp){
	qp->snd_nxt = qp->snd_una;
	qp->tlt.m_first_retx = true;
}

void RdmaHw::QpComplete(Ptr<RdmaQueuePair> qp){
	NS_ASSERT(!m_qpCompleteCallback.IsNull());
	if (m_cc_mode == 1){
		Simulator::Cancel(qp->mlx.m_eventUpdateAlpha);
		Simulator::Cancel(qp->mlx.m_eventDecreaseRate);
		Simulator::Cancel(qp->mlx.m_rpTimer);
	}
	if (qp->m_retransmit.IsRunning())
		qp->m_retransmit.Cancel();
	m_qpCompleteCallback(qp);
}

void RdmaHw::SetLinkDown(Ptr<QbbNetDevice> dev){
	printf("RdmaHw: node:%u a link down\n", m_node->GetId());
}

void RdmaHw::AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx){
	uint32_t dip = dstAddr.Get();
	m_rtTable[dip].push_back(intf_idx);
}

void RdmaHw::ClearTable(){
	m_rtTable.clear();
}

void RdmaHw::RedistributeQp(){
	// clear old qpGrp
	for (uint32_t i = 0; i < m_nic.size(); i++){
		if (m_nic[i].dev == NULL)
			continue;
		m_nic[i].qpGrp->Clear();
	}

	// redistribute qp
	for (auto &it : m_qpMap){
		Ptr<RdmaQueuePair> qp = it.second;
		uint32_t nic_idx = GetNicIdxOfQp(qp);
		m_nic[nic_idx].qpGrp->AddQp(qp);
		// Notify Nic
		m_nic[nic_idx].dev->ReassignedQp(qp);
	}
}

Ptr<Packet> RdmaHw::GetNxtPacket(Ptr<RdmaQueuePair> qp){
	uint32_t payload_size = qp->GetBytesLeft();
	if (m_mtu < payload_size)
		payload_size = m_mtu;

	uint32_t seq = (uint32_t) qp->snd_nxt;
	TltTag tlt;
	bool proceed_snd_nxt = true;
	if (qp->tlt.m_enabled) {
		if (IsWindowBasedCC()) {
			bool cond_window = !qp->IsWinBound() && (!qp->irn.m_enabled || qp->CanIrnTransmit(m_mtu));
			if ((!cond_window || !payload_size)&& qp->tlt.m_sendState == TLT_STATE_IMPORTANT && !qp->IsFinished()) {
				// TLT force transmission required
				qp->tlt.m_sendUnit = m_mtu; // Reset to MTU(MSS)
				bool tlt_success = forceSendTLT(qp, nullptr);
			}

			if (qp->tlt.m_forcetx_queue.size() > 0) {
				auto pair = qp->tlt.m_forcetx_queue.front();
				seq = pair.first;
				payload_size = pair.second;
				qp->tlt.m_forcetx_queue.pop_front();
				proceed_snd_nxt = false;
			} else if (GetCcType() == CC_TYPE_DYNAMIC_WINDOW) {
				// TODO: check if we need to intercept unimportant packet and convert to force transmission here
				// condition: if (1) CC is in recovery mode (2) not performing force retransmission (3) Pending Important (4) CC is trying to transmit seq larger than highestImportantAck
				// do we need this? this is kind of an hack for TCP. let's disable for now
				#if 0
				bool cond = false;
				if (cond) {
					int sz;
					if (forceSendTLT(qp, &sz))
					{
						NS_ASSERT(qp->tlt.m_forcetx_queue.size() > 0);
						auto pair = qp->tlt.m_forcetx_queue.front();
						seq = pair.first;
						payload_size = pair.second;
						qp->tlt.m_forcetx_queue.pop_front();
						TLT_DEBUG_PRINT("Flow " << qp->m_flow_id << " : Success in intercepting force Retransmission TLT here!! sz=" << sz);
					}
				}
				#endif
			}

			
			tlt.SetControlType(TltTag::PACKET_PAYLOAD);
			if (qp->tlt.m_sendState == TLT_STATE_IMPORTANT) {
				tlt.SetType(TltTag::PACKET_IMPORTANT);
				qp->tlt.m_sendState = TLT_STATE_IDLE;
			} else if (qp->tlt.m_sendState == TLT_STATE_SCHEDULED) {
				tlt.SetType(TltTag::PACKET_IMPORTANT_FORCE);
				qp->tlt.m_sendState = TLT_STATE_IDLE;
			} else {
				tlt.SetType(TltTag::PACKET_NOT_IMPORTANT);
				qp->tlt.m_tlt_unimportant_pkts.socketId = qp->m_flow_id;
				qp->tlt.m_tlt_unimportant_pkts.push(SequenceNumber32(seq), payload_size);  // linked list implementation of blocks
   
				qp->tlt.m_tlt_unimportant_pkts_prev_round->socketId = qp->m_flow_id;
				qp->tlt.m_tlt_unimportant_pkts_current_round->socketId = qp->m_flow_id;
				qp->tlt.m_tlt_unimportant_pkts_current_round->push(SequenceNumber32(seq), payload_size);
			}
			
			#if TLT_DEBUG_ENABLE
			char tbuf[128] = {0, };
			sprintf(tbuf, "(len %u)", payload_size);
			tlt_debug_send_print(qp, seq, tlt, std::string(tbuf));
			#endif
		} else {
			// rate-based CC will be handled below
		}
		
		qp->tlt.m_sent_pkt_count++;
	}

	qp->stat.txTotalPkts += 1;
	qp->stat.txTotalBytes += payload_size;

	Ptr<Packet> p = Create<Packet> (payload_size);
	// add SeqTsHeader
	SeqTsHeader seqTs;
	seqTs.SetSeq (seq);
	seqTs.SetPG (qp->m_pg);
	p->AddHeader (seqTs);
	// add udp header
	UdpHeader udpHeader;
	udpHeader.SetDestinationPort (qp->dport);
	udpHeader.SetSourcePort (qp->sport);
	p->AddHeader (udpHeader);
	// add ipv4 header
	Ipv4Header ipHeader;
	ipHeader.SetSource (qp->sip);
	ipHeader.SetDestination (qp->dip);
	ipHeader.SetProtocol (0x11);
	ipHeader.SetPayloadSize (p->GetSize());
	ipHeader.SetTtl (64);
	ipHeader.SetTos (0);
	ipHeader.SetIdentification (qp->m_ipid);
	p->AddHeader(ipHeader);
	// add ppp header
	PppHeader ppp;
	ppp.SetProtocol (0x0021); // EtherToPpp(0x800), see point-to-point-net-device.cc
	p->AddHeader (ppp);

	// attach Stat Tag
	uint8_t packet_pos = UINT8_MAX;
	{
		FlowIDNUMTag fint;
		if (!p->PeekPacketTag(fint)) {
			fint.SetId(qp->m_flow_id);
			fint.SetFlowSize(qp->m_size);
			p->AddPacketTag(fint);
		}
		FlowStatTag fst;
		uint64_t size = qp->m_size;
		if (!p->PeekPacketTag(fst))
		{
			if (size < m_mtu && qp->snd_nxt+payload_size >= qp->m_size) {
				fst.SetType(FlowStatTag::FLOW_START_AND_END);
			} else if (qp->snd_nxt+payload_size >= qp->m_size) {
				fst.SetType(FlowStatTag::FLOW_END);
			} else if (qp->snd_nxt == 0) {
				fst.SetType(FlowStatTag::FLOW_START);
			} else {
				fst.SetType(FlowStatTag::FLOW_NOTEND);
			}
			packet_pos = fst.GetType();
			fst.setInitiatedTime(Simulator::Now().GetSeconds());
			p->AddPacketTag(fst);
		}
	}

	if (qp->tlt.m_enabled) {
		if (!IsWindowBasedCC()) {
			// Mark packet every predefined period
			if (packet_pos == FlowStatTag::FLOW_START_AND_END || packet_pos == FlowStatTag::FLOW_END) {
				tlt.SetType(TltTag::PACKET_IMPORTANT);
				tlt.SetControlType(TltTag::PACKET_PAYLOAD_EOF);
				qp->tlt.m_last_marked_sent_pkt_count = qp->tlt.m_sent_pkt_count;
			} else if ((qp->tlt.m_sent_pkt_count-qp->tlt.m_last_marked_sent_pkt_count) % m_tlt_important_marking_interval == 0) {
				tlt.SetType(TltTag::PACKET_IMPORTANT);
				tlt.SetControlType(TltTag::PACKET_PAYLOAD_PERIODIC);
				qp->tlt.m_last_marked_sent_pkt_count = qp->tlt.m_sent_pkt_count;
			} else if (qp->tlt.m_first_retx) {
				// mark the first packet of every retransmission
				tlt.SetType(TltTag::PACKET_IMPORTANT);
				tlt.SetControlType(TltTag::PACKET_PAYLOAD_RETX);
				qp->tlt.m_last_marked_sent_pkt_count = qp->tlt.m_sent_pkt_count;
			} else {
				tlt.SetType(TltTag::PACKET_NOT_IMPORTANT);
				tlt.SetControlType(TltTag::PACKET_PAYLOAD);
			}
			#if TLT_DEBUG_ENABLE
			char tbuf[128] = {0,};
			sprintf(tbuf, "(len %u)", payload_size);
			tlt_debug_send_print(qp, seq, tlt, std::string(tbuf));
			#endif
		}
		qp->tlt.m_first_retx = false;
		p->AddPacketTag(tlt);
	}

	if (qp->irn.m_enabled) {
		if (qp->irn.m_max_seq < seq)
			qp->irn.m_max_seq = seq;
	}

	// update state
	if(proceed_snd_nxt)
		qp->snd_nxt += payload_size;
	qp->m_ipid++;

	// return
	return p;
}

void RdmaHw::PktSent(Ptr<RdmaQueuePair> qp, Ptr<Packet> pkt, Time interframeGap){
	qp->lastPktSize = pkt->GetSize();
	UpdateNextAvail(qp, interframeGap, pkt->GetSize());

	if(pkt) {
		CustomHeader ch(CustomHeader::L2_Header | CustomHeader::L3_Header | CustomHeader::L4_Header);
		pkt->PeekHeader(ch);
		if(ch.l3Prot == 0x11) { // UDP
			// Update Timer
			if (qp->m_retransmit.IsRunning())
				qp->m_retransmit.Cancel();
			qp->m_retransmit = Simulator::Schedule(qp->GetRto(m_mtu), &RdmaHw::HandleTimeout, this, qp, qp->GetRto(m_mtu));
		} else if (ch.l3Prot == 0xFC || ch.l3Prot == 0xFD|| ch.l3Prot == 0xFF) { //ACK, NACK, CNP

		}
		else if (ch.l3Prot == 0xFE)
		{ // PFC

		}
		if (m_node->GetNodeType() == 0){
			TltTag tlt;
			if (qp->tlt.m_enabled && pkt->PeekPacketTag(tlt)) {
				if (tlt.GetType() == TltTag::PACKET_IMPORTANT) {
					stat_tx.txImpBytesNIC += pkt->GetSize();
					if (tlt.GetControlType() == TltTag::PACKET_PAYLOAD)
						stat_tx.txImpBytesNIC_PL += pkt->GetSize();
					if (tlt.GetControlType() == TltTag::PACKET_ACK)
						stat_tx.txImpBytesNIC_ACK += pkt->GetSize();
					if (tlt.GetControlType() == TltTag::PACKET_NACK)
						stat_tx.txImpBytesNIC_NACK += pkt->GetSize();
					if (tlt.GetControlType() == TltTag::PACKET_CNP)
						stat_tx.txImpBytesNIC_CNP += pkt->GetSize();
					if (tlt.GetControlType() == TltTag::PACKET_PAYLOAD_EOF)
						stat_tx.txImpBytesNIC_PLE += pkt->GetSize();
					if (tlt.GetControlType() == TltTag::PACKET_PAYLOAD_RETX)
						stat_tx.txImpBytesNIC_PLR += pkt->GetSize();
				} else if (tlt.GetType() == TltTag::PACKET_IMPORTANT_ECHO) {
					stat_tx.txImpEBytesNIC += pkt->GetSize();
				} else if (tlt.GetType() == TltTag::PACKET_IMPORTANT_FORCE) {
					stat_tx.txImpFBytesNIC += pkt->GetSize();
				} else if (tlt.GetType() == TltTag::PACKET_IMPORTANT_ECHO_FORCE) {
					stat_tx.txImpEFBytesNIC += pkt->GetSize();
				} else if (tlt.GetType() == TltTag::PACKET_IMPORTANT_CONTROL) {
					stat_tx.txImpCBytesNIC += pkt->GetSize();
				} else if (tlt.GetType() == TltTag::PACKET_NOT_IMPORTANT) {
					stat_tx.txUimpBytesNIC += pkt->GetSize();
				}
			}
		}
	}
}

void RdmaHw::HandleTimeout(Ptr<RdmaQueuePair> qp, Time rto) {
	

	// Assume Outstanding Packets are lost
	// std::cerr << "Timeout on qp=" << qp << std::endl;

	if (qp->IsFinished())
	{
		// std::cerr << "Why still scheduled?" << std::endl;
		return;
	}

	uint32_t nic_idx = GetNicIdxOfQp(qp);
	Ptr<QbbNetDevice> dev = m_nic[nic_idx].dev;

	// IRN: disable timeouts when PFC is enabled to prevent spurious retransmissions
	if (qp->irn.m_enabled && dev->IsQbbEnabled())
		return;

	stat_tx.RetxTimeoutCnt++;

	if (qp->tlt.m_enabled) {
		std::cerr << "Warning: TLT Timeout Detected." << std::endl;
	}

	if (qp->tlt.m_enabled && IsWindowBasedCC()) {
		qp->tlt.m_sendState = TLT_STATE_IMPORTANT;
		qp->tlt.m_sent_fin = false;
	}

	if (acc_timeout_count.find(qp->m_flow_id) == acc_timeout_count.end())
		acc_timeout_count[qp->m_flow_id] = 0;
	acc_timeout_count[qp->m_flow_id]++;

	if (qp->irn.m_enabled)
		qp->irn.m_recovery = true;
		
	RecoverQueue(qp);
	dev->TriggerTransmit();
}

void RdmaHw::UpdateNextAvail(Ptr<RdmaQueuePair> qp, Time interframeGap, uint32_t pkt_size){
	Time sendingTime;
	if (m_rateBound)
		sendingTime = interframeGap + Seconds(qp->m_rate.CalculateTxTime(pkt_size));
	else
		sendingTime = interframeGap + Seconds(qp->m_max_rate.CalculateTxTime(pkt_size));
	qp->m_nextAvail = Simulator::Now() + sendingTime;
}

void RdmaHw::ChangeRate(Ptr<RdmaQueuePair> qp, DataRate new_rate){
	#if 1
	Time sendingTime = Seconds(qp->m_rate.CalculateTxTime(qp->lastPktSize));
	Time new_sendintTime = Seconds(new_rate.CalculateTxTime(qp->lastPktSize));
	qp->m_nextAvail = qp->m_nextAvail + new_sendintTime - sendingTime;
	// update nic's next avail event
	uint32_t nic_idx = GetNicIdxOfQp(qp);
	m_nic[nic_idx].dev->UpdateNextAvail(qp->m_nextAvail);
	#endif

	// change to new rate
	qp->m_rate = new_rate;
}

#define PRINT_LOG 0
/******************************
 * Mellanox's version of DCQCN
 *****************************/
void RdmaHw::UpdateAlphaMlx(Ptr<RdmaQueuePair> q){
	#if PRINT_LOG
	//std::cout << Simulator::Now() << " alpha update:" << m_node->GetId() << ' ' << q->mlx.m_alpha << ' ' << (int)q->mlx.m_alpha_cnp_arrived << '\n';
	//printf("%lu alpha update: %08x %08x %u %u %.6lf->", Simulator::Now().GetTimeStep(), q->sip.Get(), q->dip.Get(), q->sport, q->dport, q->mlx.m_alpha);
	#endif
	if (q->mlx.m_alpha_cnp_arrived){
		q->mlx.m_alpha = (1 - m_g)*q->mlx.m_alpha + m_g; 	//binary feedback
	}else {
		q->mlx.m_alpha = (1 - m_g)*q->mlx.m_alpha; 	//binary feedback
	}
	#if PRINT_LOG
	//printf("%.6lf\n", q->mlx.m_alpha);
	#endif
	q->mlx.m_alpha_cnp_arrived = false; // clear the CNP_arrived bit
	ScheduleUpdateAlphaMlx(q);
}
void RdmaHw::ScheduleUpdateAlphaMlx(Ptr<RdmaQueuePair> q){
	q->mlx.m_eventUpdateAlpha = Simulator::Schedule(MicroSeconds(m_alpha_resume_interval), &RdmaHw::UpdateAlphaMlx, this, q);
}

void RdmaHw::cnp_received_mlx(Ptr<RdmaQueuePair> q){
	q->mlx.m_alpha_cnp_arrived = true; // set CNP_arrived bit for alpha update
	q->mlx.m_decrease_cnp_arrived = true; // set CNP_arrived bit for rate decrease
	if (q->mlx.m_first_cnp){
		// init alpha
		q->mlx.m_alpha = 1;
		q->mlx.m_alpha_cnp_arrived = false;
		// schedule alpha update
		ScheduleUpdateAlphaMlx(q);
		// schedule rate decrease
		ScheduleDecreaseRateMlx(q, 1); // add 1 ns to make sure rate decrease is after alpha update
		// set rate on first CNP
		q->mlx.m_targetRate = q->m_rate = m_rateOnFirstCNP * q->m_rate;
		q->mlx.m_first_cnp = false;
	}
}

void RdmaHw::CheckRateDecreaseMlx(Ptr<RdmaQueuePair> q){
	ScheduleDecreaseRateMlx(q, 0);
	if (q->mlx.m_decrease_cnp_arrived){
		#if PRINT_LOG
		printf("%lu rate dec: %08x %08x %u %u (%0.3lf %.3lf)->", Simulator::Now().GetTimeStep(), q->sip.Get(), q->dip.Get(), q->sport, q->dport, q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
		#endif
		bool clamp = true;
		if (!m_EcnClampTgtRate){
			if (q->mlx.m_rpTimeStage == 0)
				clamp = false;
		}
		if (clamp)
			q->mlx.m_targetRate = q->m_rate;
		q->m_rate = std::max(m_minRate, q->m_rate * (1 - q->mlx.m_alpha / 2));
		// reset rate increase related things
		q->mlx.m_rpTimeStage = 0;
		q->mlx.m_decrease_cnp_arrived = false;
		Simulator::Cancel(q->mlx.m_rpTimer);
		q->mlx.m_rpTimer = Simulator::Schedule(MicroSeconds(m_rpgTimeReset), &RdmaHw::RateIncEventTimerMlx, this, q);
		#if PRINT_LOG
		printf("(%.3lf %.3lf)\n", q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
		#endif
	}
}
void RdmaHw::ScheduleDecreaseRateMlx(Ptr<RdmaQueuePair> q, uint32_t delta){
	q->mlx.m_eventDecreaseRate = Simulator::Schedule(MicroSeconds(m_rateDecreaseInterval) + NanoSeconds(delta), &RdmaHw::CheckRateDecreaseMlx, this, q);
}

void RdmaHw::RateIncEventTimerMlx(Ptr<RdmaQueuePair> q){
	q->mlx.m_rpTimer = Simulator::Schedule(MicroSeconds(m_rpgTimeReset), &RdmaHw::RateIncEventTimerMlx, this, q);
	RateIncEventMlx(q);
	q->mlx.m_rpTimeStage++;
}
void RdmaHw::RateIncEventMlx(Ptr<RdmaQueuePair> q){
	// check which increase phase: fast recovery, active increase, hyper increase
	if (q->mlx.m_rpTimeStage < m_rpgThreshold){ // fast recovery
		FastRecoveryMlx(q);
	}else if (q->mlx.m_rpTimeStage == m_rpgThreshold){ // active increase
		ActiveIncreaseMlx(q);
	}else { // hyper increase
		HyperIncreaseMlx(q);
	}
}

void RdmaHw::FastRecoveryMlx(Ptr<RdmaQueuePair> q){
	#if PRINT_LOG
	printf("%lu fast recovery: %08x %08x %u %u (%0.3lf %.3lf)->", Simulator::Now().GetTimeStep(), q->sip.Get(), q->dip.Get(), q->sport, q->dport, q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
	#endif
	q->m_rate = (q->m_rate / 2) + (q->mlx.m_targetRate / 2);
	#if PRINT_LOG
	printf("(%.3lf %.3lf)\n", q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
	#endif
}
void RdmaHw::ActiveIncreaseMlx(Ptr<RdmaQueuePair> q){
	#if PRINT_LOG
	printf("%lu active inc: %08x %08x %u %u (%0.3lf %.3lf)->", Simulator::Now().GetTimeStep(), q->sip.Get(), q->dip.Get(), q->sport, q->dport, q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
	#endif
	// get NIC
	uint32_t nic_idx = GetNicIdxOfQp(q);
	Ptr<QbbNetDevice> dev = m_nic[nic_idx].dev;
	// increate rate
	q->mlx.m_targetRate += m_rai;
	if (q->mlx.m_targetRate > dev->GetDataRate())
		q->mlx.m_targetRate = dev->GetDataRate();
	q->m_rate = (q->m_rate / 2) + (q->mlx.m_targetRate / 2);
	#if PRINT_LOG
	printf("(%.3lf %.3lf)\n", q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
	#endif
}
void RdmaHw::HyperIncreaseMlx(Ptr<RdmaQueuePair> q){
	#if PRINT_LOG
	printf("%lu hyper inc: %08x %08x %u %u (%0.3lf %.3lf)->", Simulator::Now().GetTimeStep(), q->sip.Get(), q->dip.Get(), q->sport, q->dport, q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
	#endif
	// get NIC
	uint32_t nic_idx = GetNicIdxOfQp(q);
	Ptr<QbbNetDevice> dev = m_nic[nic_idx].dev;
	// increate rate
	q->mlx.m_targetRate += m_rhai;
	if (q->mlx.m_targetRate > dev->GetDataRate())
		q->mlx.m_targetRate = dev->GetDataRate();
	q->m_rate = (q->m_rate / 2) + (q->mlx.m_targetRate / 2);
	#if PRINT_LOG
	printf("(%.3lf %.3lf)\n", q->mlx.m_targetRate.GetBitRate() * 1e-9, q->m_rate.GetBitRate() * 1e-9);
	#endif
}

/***********************
 * High Precision CC
 ***********************/
void RdmaHw::HandleAckHp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch){
	uint32_t ack_seq = ch.ack.seq;
	// update rate
	if (ack_seq > qp->hp.m_lastUpdateSeq){ // if full RTT feedback is ready, do full update
		UpdateRateHp(qp, p, ch, false);
	}else{ // do fast react
		FastReactHp(qp, p, ch);
	}
}

void RdmaHw::UpdateRateHp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool fast_react){
	uint32_t next_seq = qp->snd_nxt;
	bool print = !fast_react || true;
	if (qp->hp.m_lastUpdateSeq == 0){ // first RTT
		qp->hp.m_lastUpdateSeq = next_seq;
		// store INT
		IntHeader &ih = ch.ack.ih;
		NS_ASSERT(ih.nhop <= IntHeader::maxHop);
		for (uint32_t i = 0; i < ih.nhop; i++)
			qp->hp.hop[i] = ih.hop[i];
		#if PRINT_LOG
		if (print){
			printf("%lu %s %08x %08x %u %u [%u,%u,%u]", Simulator::Now().GetTimeStep(), fast_react? "fast" : "update", qp->sip.Get(), qp->dip.Get(), qp->sport, qp->dport, qp->hp.m_lastUpdateSeq, ch.ack.seq, next_seq);
			for (uint32_t i = 0; i < ih.nhop; i++)
				printf(" %u %lu %lu", ih.hop[i].GetQlen(), ih.hop[i].GetBytes(), ih.hop[i].GetTime());
			printf("\n");
		}
		#endif
	}else {
		// check packet INT
		IntHeader &ih = ch.ack.ih;
		if (ih.nhop <= IntHeader::maxHop){
			double max_c = 0;
			bool inStable = false;
			#if PRINT_LOG
			if (print)
				printf("%lu %s %08x %08x %u %u [%u,%u,%u]", Simulator::Now().GetTimeStep(), fast_react? "fast" : "update", qp->sip.Get(), qp->dip.Get(), qp->sport, qp->dport, qp->hp.m_lastUpdateSeq, ch.ack.seq, next_seq);
			#endif
			// check each hop
			double U = 0;
			uint64_t dt = 0;
			bool updated[IntHeader::maxHop] = {false}, updated_any = false;
			NS_ASSERT(ih.nhop <= IntHeader::maxHop);
			for (uint32_t i = 0; i < ih.nhop; i++){
				if (m_sampleFeedback){
					if (ih.hop[i].GetQlen() == 0 and fast_react)
						continue;
				}
				updated[i] = updated_any = true;
				#if PRINT_LOG
				if (print)
					printf(" %u(%u) %lu(%lu) %lu(%lu)", ih.hop[i].GetQlen(), qp->hp.hop[i].GetQlen(), ih.hop[i].GetBytes(), qp->hp.hop[i].GetBytes(), ih.hop[i].GetTime(), qp->hp.hop[i].GetTime());
				#endif
				uint64_t tau = ih.hop[i].GetTimeDelta(qp->hp.hop[i]);;
				double duration = tau * 1e-9;
				double txRate = (ih.hop[i].GetBytesDelta(qp->hp.hop[i])) * 8 / duration;
				double u = txRate / ih.hop[i].GetLineRate() + (double)std::min(ih.hop[i].GetQlen(), qp->hp.hop[i].GetQlen()) * qp->m_max_rate.GetBitRate() / ih.hop[i].GetLineRate() /qp->m_win;
				#if PRINT_LOG
				if (print)
					printf(" %.3lf %.3lf", txRate, u);
				#endif
				if (!m_multipleRate){
					// for aggregate (single R)
					if (u > U){
						U = u;
						dt = tau;
					}
				}else {
					// for per hop (per hop R)
					if (tau > qp->m_baseRtt)
						tau = qp->m_baseRtt;
					qp->hp.hopState[i].u = (qp->hp.hopState[i].u * (qp->m_baseRtt - tau) + u * tau) / double(qp->m_baseRtt);
				}
				qp->hp.hop[i] = ih.hop[i];
			}

			DataRate new_rate;
			int32_t new_incStage;
			DataRate new_rate_per_hop[IntHeader::maxHop];
			int32_t new_incStage_per_hop[IntHeader::maxHop];
			if (!m_multipleRate){
				// for aggregate (single R)
				if (updated_any){
					if (dt > qp->m_baseRtt)
						dt = qp->m_baseRtt;
					qp->hp.u = (qp->hp.u * (qp->m_baseRtt - dt) + U * dt) / double(qp->m_baseRtt);
					max_c = qp->hp.u / m_targetUtil;

					if (max_c >= 1 || qp->hp.m_incStage >= m_miThresh){
						new_rate = qp->hp.m_curRate / max_c + m_rai;
						new_incStage = 0;
					}else{
						new_rate = qp->hp.m_curRate + m_rai;
						new_incStage = qp->hp.m_incStage+1;
					}
					if (new_rate < m_minRate)
						new_rate = m_minRate;
					if (new_rate > qp->m_max_rate)
						new_rate = qp->m_max_rate;
					#if PRINT_LOG
					if (print)
						printf(" u=%.6lf U=%.3lf dt=%u max_c=%.3lf", qp->hp.u, U, dt, max_c);
					#endif
					#if PRINT_LOG
					if (print)
						printf(" rate:%.3lf->%.3lf\n", qp->hp.m_curRate.GetBitRate()*1e-9, new_rate.GetBitRate()*1e-9);
					#endif
				}
			}else{
				// for per hop (per hop R)
				new_rate = qp->m_max_rate;
				for (uint32_t i = 0; i < ih.nhop; i++){
					if (updated[i]){
						double c = qp->hp.hopState[i].u / m_targetUtil;
						if (c >= 1 || qp->hp.hopState[i].incStage >= m_miThresh){
							new_rate_per_hop[i] = qp->hp.hopState[i].Rc / c + m_rai;
							new_incStage_per_hop[i] = 0;
						}else{
							new_rate_per_hop[i] = qp->hp.hopState[i].Rc + m_rai;
							new_incStage_per_hop[i] = qp->hp.hopState[i].incStage+1;
						}
						// bound rate
						if (new_rate_per_hop[i] < m_minRate)
							new_rate_per_hop[i] = m_minRate;
						if (new_rate_per_hop[i] > qp->m_max_rate)
							new_rate_per_hop[i] = qp->m_max_rate;
						// find min new_rate
						if (new_rate_per_hop[i] < new_rate)
							new_rate = new_rate_per_hop[i];
						#if PRINT_LOG
						if (print)
							printf(" [%u]u=%.6lf c=%.3lf", i, qp->hp.hopState[i].u, c);
						#endif
						#if PRINT_LOG
						if (print)
							printf(" %.3lf->%.3lf", qp->hp.hopState[i].Rc.GetBitRate()*1e-9, new_rate.GetBitRate()*1e-9);
						#endif
					}else{
						if (qp->hp.hopState[i].Rc < new_rate)
							new_rate = qp->hp.hopState[i].Rc;
					}
				}
				#if PRINT_LOG
				printf("\n");
				#endif
			}
			if (updated_any)
				ChangeRate(qp, new_rate);
			if (!fast_react){
				if (updated_any){
					qp->hp.m_curRate = new_rate;
					qp->hp.m_incStage = new_incStage;
				}
				if (m_multipleRate){
					// for per hop (per hop R)
					for (uint32_t i = 0; i < ih.nhop; i++){
						if (updated[i]){
							qp->hp.hopState[i].Rc = new_rate_per_hop[i];
							qp->hp.hopState[i].incStage = new_incStage_per_hop[i];
						}
					}
				}
			}
		}
		if (!fast_react){
			if (next_seq > qp->hp.m_lastUpdateSeq)
				qp->hp.m_lastUpdateSeq = next_seq; //+ rand() % 2 * m_mtu;
		}
	}
}

void RdmaHw::FastReactHp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch){
	if (m_fast_react)
		UpdateRateHp(qp, p, ch, true);
}

/**********************
 * TIMELY
 *********************/
void RdmaHw::HandleAckTimely(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch){
	uint32_t ack_seq = ch.ack.seq;
	// update rate
	if (ack_seq > qp->tmly.m_lastUpdateSeq){ // if full RTT feedback is ready, do full update
		UpdateRateTimely(qp, p, ch, false);
	}else{ // do fast react
		FastReactTimely(qp, p, ch);
	}
}
void RdmaHw::UpdateRateTimely(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool us){
	uint32_t next_seq = qp->snd_nxt;
	uint64_t rtt = Simulator::Now().GetTimeStep() - ch.ack.ih.ts;
	bool print = !us;
	if (qp->tmly.m_lastUpdateSeq != 0){ // not first RTT
		int64_t new_rtt_diff = (int64_t)rtt - (int64_t)qp->tmly.lastRtt;
		double rtt_diff = (1 - m_tmly_alpha) * qp->tmly.rttDiff + m_tmly_alpha * new_rtt_diff;
		double gradient = rtt_diff / m_tmly_minRtt;
		bool inc = false;
		double c = 0;
		#if PRINT_LOG
		if (print)
			printf("%lu node:%u rtt:%lu rttDiff:%.0lf gradient:%.3lf rate:%.3lf", Simulator::Now().GetTimeStep(), m_node->GetId(), rtt, rtt_diff, gradient, qp->tmly.m_curRate.GetBitRate() * 1e-9);
		#endif
		if (rtt < m_tmly_TLow){
			inc = true;
		}else if (rtt > m_tmly_THigh){
			c = 1 - m_tmly_beta * (1 - (double)m_tmly_THigh / rtt);
			inc = false;
		}else if (gradient <= 0){
			inc = true;
		}else{
			c = 1 - m_tmly_beta * gradient;
			if (c < 0)
				c = 0;
			inc = false;
		}
		if (inc){
			if (qp->tmly.m_incStage < 5){
				qp->m_rate = qp->tmly.m_curRate + m_rai;
			}else{
				qp->m_rate = qp->tmly.m_curRate + m_rhai;
			}
			if (qp->m_rate > qp->m_max_rate)
				qp->m_rate = qp->m_max_rate;
			if (!us){
				qp->tmly.m_curRate = qp->m_rate;
				qp->tmly.m_incStage++;
				qp->tmly.rttDiff = rtt_diff;
			}
		}else{
			qp->m_rate = std::max(m_minRate, qp->tmly.m_curRate * c); 
			if (!us){
				qp->tmly.m_curRate = qp->m_rate;
				qp->tmly.m_incStage = 0;
				qp->tmly.rttDiff = rtt_diff;
			}
		}
		#if PRINT_LOG
		if (print){
			printf(" %c %.3lf\n", inc? '^':'v', qp->m_rate.GetBitRate() * 1e-9);
		}
		#endif
	}
	if (!us && next_seq > qp->tmly.m_lastUpdateSeq){
		qp->tmly.m_lastUpdateSeq = next_seq;
		// update
		qp->tmly.lastRtt = rtt;
	}
}
void RdmaHw::FastReactTimely(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch){
}

/**********************
 * DCTCP
 *********************/
void RdmaHw::HandleAckDctcp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch){
	uint32_t ack_seq = ch.ack.seq;
	uint8_t cnp = (ch.ack.flags >> qbbHeader::FLAG_CNP) & 1;
	bool new_batch = false;

	// update alpha
	qp->dctcp.m_ecnCnt += (cnp > 0);
	if (ack_seq > qp->dctcp.m_lastUpdateSeq){ // if full RTT feedback is ready, do alpha update
		#if PRINT_LOG
		printf("%lu %s %08x %08x %u %u [%u,%u,%u] %.3lf->", Simulator::Now().GetTimeStep(), "alpha", qp->sip.Get(), qp->dip.Get(), qp->sport, qp->dport, qp->dctcp.m_lastUpdateSeq, ch.ack.seq, qp->snd_nxt, qp->dctcp.m_alpha);
		#endif
		new_batch = true;
		if (qp->dctcp.m_lastUpdateSeq == 0){ // first RTT
			qp->dctcp.m_lastUpdateSeq = qp->snd_nxt;
			qp->dctcp.m_batchSizeOfAlpha = qp->snd_nxt / m_mtu + 1;
		}else {
			double frac = std::min(1.0, double(qp->dctcp.m_ecnCnt) / qp->dctcp.m_batchSizeOfAlpha);
			qp->dctcp.m_alpha = (1 - m_g) * qp->dctcp.m_alpha + m_g * frac;
			qp->dctcp.m_lastUpdateSeq = qp->snd_nxt;
			qp->dctcp.m_ecnCnt = 0;
			qp->dctcp.m_batchSizeOfAlpha = (qp->snd_nxt - ack_seq) / m_mtu + 1;
			#if PRINT_LOG
			printf("%.3lf F:%.3lf", qp->dctcp.m_alpha, frac);
			#endif
		}
		#if PRINT_LOG
		printf("\n");
		#endif
	}

	// check cwr exit
	if (qp->dctcp.m_caState == 1){
		if (ack_seq > qp->dctcp.m_highSeq)
			qp->dctcp.m_caState = 0;
	}

	// check if need to reduce rate: ECN and not in CWR
	if (cnp && qp->dctcp.m_caState == 0){
		#if PRINT_LOG
		printf("%lu %s %08x %08x %u %u %.3lf->", Simulator::Now().GetTimeStep(), "rate", qp->sip.Get(), qp->dip.Get(), qp->sport, qp->dport, qp->m_rate.GetBitRate()*1e-9);
		#endif
		qp->m_rate = std::max(m_minRate, qp->m_rate * (1 - qp->dctcp.m_alpha / 2));
		#if PRINT_LOG
		printf("%.3lf\n", qp->m_rate.GetBitRate() * 1e-9);
		#endif
		qp->dctcp.m_caState = 1;
		qp->dctcp.m_highSeq = qp->snd_nxt;
	}

	// additive inc
	if (qp->dctcp.m_caState == 0 && new_batch)
		qp->m_rate = std::min(qp->m_max_rate, qp->m_rate + m_dctcp_rai);
}

}
