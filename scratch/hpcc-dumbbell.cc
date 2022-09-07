/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation;
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#undef PGO_TRAINING
#define PATH_TO_PGO_CONFIG "path_to_pgo_config"

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <time.h> 
#include "ns3/core-module.h"
#include "ns3/qbb-helper.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/applications-module.h"
#include "ns3/internet-module.h"
#include "ns3/global-route-manager.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/broadcom-node.h"
#include "ns3/packet.h"
#include "ns3/error-model.h"
#include <ns3/rdma.h>
#include <ns3/rdma-client.h>
#include <ns3/rdma-client-helper.h>
#include <ns3/rdma-driver.h>
#include <ns3/switch-node.h>
#include <ns3/sim-setting.h>
#include <ns3/assert.h>

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("GENERIC_SIMULATION");

uint32_t cc_mode = 1;
bool enable_qcn = true, enable_pfc = true, use_dynamic_pfc_threshold = true;
uint32_t packet_payload_size = 1000, l2_chunk_size = 0, l2_ack_interval = 0;
double pause_time = 671, simulator_stop_time = 3.01;  // pause_time = 65535*(64Bytes/50Gbps)
std::string data_rate, link_delay, topology_file, flow_file, trace_file, trace_output_file;
std::string fct_output_file = "fct.txt";
std::string pfc_output_file = "pfc.txt";

double alpha_resume_interval = 55, rp_timer, ewma_gain = 1 / 16;
double rate_decrease_interval = 4;
uint32_t fast_recovery_times = 5;
std::string rate_ai, rate_hai, min_rate = "100Mb/s";
std::string dctcp_rate_ai = "1000Mb/s";

bool clamp_target_rate = false, l2_back_to_zero = false;
double error_rate_per_link = 0.0;
uint32_t has_win = 1;
uint32_t global_t = 1;
uint32_t mi_thresh = 5;
bool var_win = false, fast_react = true;
bool multi_rate = true;
bool sample_feedback = false;
double u_target = 0.95;
uint32_t int_multi = 1;
bool rate_bound = true;

uint32_t ack_high_prio = 0;
uint64_t link_down_time = 0;
uint32_t link_down_A = 0, link_down_B = 0;

uint32_t enable_trace = 1;

uint32_t buffer_size = 0; // 0 to set buffer size automatically

uint32_t qlen_dump_interval = 100000000, qlen_mon_interval = 100;
uint64_t qlen_mon_start = 2000000000, qlen_mon_end = 2100000000;
string qlen_mon_file;

// Added from Here
string hpcc_workload;
double load = 0.1;
double foreground_flow_ratio = 0.01, app_start_time = 0.01, app_stop_time = 100;
uint32_t incast_flow_size = 64000; // previously  dctcp_tx_bytes
const int FOREGROUND_INCAST_FLOW_PER_HOST = 4;
int num_bg_flows= 0;
double last_background_flow_time = 0;
int enable_irn = 0, enable_tlt = 0;
double tlt_maxbytes_uip = 0;
bool irn_no_bdpfc = false;

int dumbbell_numhost = 1, dumbbell_numflowperhost = 1, dumbbell_flowsize = 10000;
double dumbbell_errorrate = 0.0;
std::string dumbbell_linkcap = "50Gbps";
#define MAP_KEY_EXISTS(map, key) (((map).find(key) != (map).end()))

unordered_map<uint64_t, uint32_t>
	rate2kmax,
	rate2kmin;
unordered_map<uint64_t, double> rate2pmax;


uint64_t nic_rate;

uint64_t maxRtt, maxBdp;

struct Interface{
	uint32_t idx;
	bool up;
	uint64_t delay;
	uint64_t bw;

	Interface() : idx(0), up(false){}
};
map<Ptr<Node>, map<Ptr<Node>, Interface> > nbr2if;
// Mapping destination to next hop for each node: <node, <dest, <nexthop0, ...> > >
map<Ptr<Node>, map<Ptr<Node>, vector<Ptr<Node> > > > nextHop;
map<Ptr<Node>, map<Ptr<Node>, uint64_t> > pairDelay;
map<Ptr<Node>, map<Ptr<Node>, uint64_t> > pairTxDelay;
map<Ptr<Node>, map<Ptr<Node>, uint64_t> > pairBw;
map<Ptr<Node>, map<Ptr<Node>, uint64_t> > pairBdp;
map<Ptr<Node>, map<Ptr<Node>, uint64_t> > pairRtt;

void qp_finish(FILE* fout, Ptr<RdmaQueuePair> q){
	//fprintf(fout, "%lu QP complete\n", Simulator::Now().GetTimeStep());
	fprintf(fout, "%08x %08x %u %u %lu %lu %lu\n", q->sip.Get(), q->dip.Get(), q->sport, q->dport, q->m_size, q->startTime.GetTimeStep(), (Simulator::Now() - q->startTime).GetTimeStep());
	fflush(fout);
}

void get_pfc(FILE* fout, Ptr<QbbNetDevice> dev, uint32_t type){
	fprintf(fout, "%lu %u %u %u %u\n", Simulator::Now().GetTimeStep(), dev->GetNode()->GetId(), dev->GetNode()->GetNodeType(), dev->GetIfIndex(), type);
}

struct QlenDistribution{
	vector<uint32_t> cnt; // cnt[i] is the number of times that the queue len is i KB

	void add(uint32_t qlen){
		uint32_t kb = qlen / 1000;
		if (cnt.size() < kb+1)
			cnt.resize(kb+1);
		cnt[kb]++;
	}
};
map<uint32_t, map<uint32_t, QlenDistribution> > queue_result;
void monitor_buffer(FILE* qlen_output, NodeContainer *n){
	for (uint32_t i = 0; i < n->GetN(); i++){
		if (n->Get(i)->GetNodeType() == 1){ // is switch
			Ptr<SwitchNode> sw = DynamicCast<SwitchNode>(n->Get(i));
			if (queue_result.find(i) == queue_result.end())
				queue_result[i];
			for (uint32_t j = 1; j < sw->GetNDevices(); j++){
				uint32_t size = 0;
				for (uint32_t k = 0; k < SwitchMmu::qCnt; k++)
					size += sw->m_mmu->egress_bytes[j][k];
				queue_result[i][j].add(size);
			}
		}
	}
	if (Simulator::Now().GetTimeStep() % qlen_dump_interval == 0){
		fprintf(qlen_output, "time: %lu\n", Simulator::Now().GetTimeStep());
		for (auto &it0 : queue_result)
			for (auto &it1 : it0.second){
				fprintf(qlen_output, "%u %u", it0.first, it1.first);
				auto &dist = it1.second.cnt;
				for (uint32_t i = 0; i < dist.size(); i++)
					fprintf(qlen_output, " %u", dist[i]);
				fprintf(qlen_output, "\n");
			}
		fflush(qlen_output);
	}
	if (Simulator::Now().GetTimeStep() < qlen_mon_end)
		Simulator::Schedule(NanoSeconds(qlen_mon_interval), &monitor_buffer, qlen_output, n);
}

void CalculateRoute(Ptr<Node> host){
	// queue for the BFS.
	vector<Ptr<Node> > q;
	// Distance from the host to each node.
	map<Ptr<Node>, int> dis;
	map<Ptr<Node>, uint64_t> delay;
	map<Ptr<Node>, uint64_t> txDelay;
	map<Ptr<Node>, uint64_t> bw;
	// init BFS.
	q.push_back(host);
	dis[host] = 0;
	delay[host] = 0;
	txDelay[host] = 0;
	bw[host] = 0xfffffffffffffffflu;
	// BFS.
	for (int i = 0; i < (int)q.size(); i++){
		Ptr<Node> now = q[i];
		int d = dis[now];
		for (auto it = nbr2if[now].begin(); it != nbr2if[now].end(); it++){
			// skip down link
			if (!it->second.up)
				continue;
			Ptr<Node> next = it->first;
			// If 'next' have not been visited.
			if (dis.find(next) == dis.end()){
				dis[next] = d + 1;
				delay[next] = delay[now] + it->second.delay;
				txDelay[next] = txDelay[now] + packet_payload_size * 1000000000lu * 8 / it->second.bw;
				bw[next] = std::min(bw[now], it->second.bw);
				// we only enqueue switch, because we do not want packets to go through host as middle point
				if (next->GetNodeType() == 1)
					q.push_back(next);
			}
			// if 'now' is on the shortest path from 'next' to 'host'.
			if (d + 1 == dis[next]){
				nextHop[next][host].push_back(now);
			}
		}
	}
	for (auto it : delay)
		pairDelay[it.first][host] = it.second;
	for (auto it : txDelay)
		pairTxDelay[it.first][host] = it.second;
	for (auto it : bw)
		pairBw[it.first][host] = it.second;
}

void CalculateRoutes(NodeContainer &n){
	for (int i = 0; i < (int)n.GetN(); i++){
		Ptr<Node> node = n.Get(i);
		if (node->GetNodeType() == 0)
			CalculateRoute(node);
	}
}

void SetRoutingEntries(){
	// For each node.
	for (auto i = nextHop.begin(); i != nextHop.end(); i++){
		Ptr<Node> node = i->first;
		auto &table = i->second;
		for (auto j = table.begin(); j != table.end(); j++){
			// The destination node.
			Ptr<Node> dst = j->first;
			// The IP address of the dst.
			Ipv4Address dstAddr = dst->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();
			// The next hops towards the dst.
			vector<Ptr<Node> > nexts = j->second;
			for (int k = 0; k < (int)nexts.size(); k++){
				Ptr<Node> next = nexts[k];
				uint32_t interface = nbr2if[node][next].idx;
				if (node->GetNodeType() == 1)
					DynamicCast<SwitchNode>(node)->AddTableEntry(dstAddr, interface);
				else{
					node->GetObject<RdmaDriver>()->m_rdma->AddTableEntry(dstAddr, interface);
				}
			}
		}
	}
}

// take down the link between a and b, and redo the routing
void TakeDownLink(NodeContainer n, Ptr<Node> a, Ptr<Node> b){
	if (!nbr2if[a][b].up)
		return;
	// take down link between a and b
	nbr2if[a][b].up = nbr2if[b][a].up = false;
	nextHop.clear();
	CalculateRoutes(n);
	// clear routing tables
	for (uint32_t i = 0; i < n.GetN(); i++){
		if (n.Get(i)->GetNodeType() == 1)
			DynamicCast<SwitchNode>(n.Get(i))->ClearTable();
		else
			n.Get(i)->GetObject<RdmaDriver>()->m_rdma->ClearTable();
	}
	DynamicCast<QbbNetDevice>(a->GetDevice(nbr2if[a][b].idx))->TakeDown();
	DynamicCast<QbbNetDevice>(b->GetDevice(nbr2if[b][a].idx))->TakeDown();
	// reset routing table
	SetRoutingEntries();

	// redistribute qp on each host
	for (uint32_t i = 0; i < n.GetN(); i++){
		if (n.Get(i)->GetNodeType() == 0)
			n.Get(i)->GetObject<RdmaDriver>()->m_rdma->RedistributeQp();
	}
}

uint64_t get_nic_rate(NodeContainer &n){
	for (uint32_t i = 0; i < n.GetN(); i++)
		if (n.Get(i)->GetNodeType() == 0)
			return DynamicCast<QbbNetDevice>(n.Get(i)->GetDevice(1))->GetDataRate().GetBitRate();
}


bool load_workload(const char *workload_file, uint32_t **workload_cdf);



int main(int argc, char *argv[])
{
	// LogComponentEnable("SelectivePacketQueue", LOG_LEVEL_LOGIC);
	
	uint32_t *workload_cdf = nullptr;

	clock_t begint, endt;
	begint = clock();
#ifndef PGO_TRAINING
	if (argc > 1)
#else
	if (true)
#endif
	{
		//Read the configuration file
		std::ifstream conf;
#ifndef PGO_TRAINING
		conf.open(argv[1]);
#else
		conf.open(PATH_TO_PGO_CONFIG);
#endif
		while (!conf.eof())
		{
			std::string key;
			conf >> key;

			//std::cerr << conf.cur << "\n";

			if (key.compare("ENABLE_PFC") == 0)
			{
				uint32_t v;
				conf >> v;
				enable_pfc = v;
				if (enable_pfc)
					std::cerr << "ENABLE_PFC\t\t\t" << "Yes" << "\n";
				else
					std::cerr << "ENABLE_PFC\t\t\t" << "No" << "\n";
			}
			else if (key.compare("ENABLE_QCN") == 0)
			{
				uint32_t v;
				conf >> v;
				enable_qcn = v;
				if (enable_qcn)
					std::cerr << "ENABLE_QCN\t\t\t" << "Yes" << "\n";
				else
					std::cerr << "ENABLE_QCN\t\t\t" << "No" << "\n";
			}
			else if (key.compare("USE_DYNAMIC_PFC_THRESHOLD") == 0)
			{
				uint32_t v;
				conf >> v;
				use_dynamic_pfc_threshold = v;
				if (use_dynamic_pfc_threshold)
					std::cerr << "USE_DYNAMIC_PFC_THRESHOLD\t" << "Yes" << "\n";
				else
					std::cerr << "USE_DYNAMIC_PFC_THRESHOLD\t" << "No" << "\n";
			}
			else if (key.compare("CLAMP_TARGET_RATE") == 0)
			{
				uint32_t v;
				conf >> v;
				clamp_target_rate = v;
				if (clamp_target_rate)
					std::cerr << "CLAMP_TARGET_RATE\t\t" << "Yes" << "\n";
				else
					std::cerr << "CLAMP_TARGET_RATE\t\t" << "No" << "\n";
			}
			else if (key.compare("PAUSE_TIME") == 0)
			{
				double v;
				conf >> v;
				pause_time = v;
				std::cerr << "PAUSE_TIME\t\t\t" << pause_time << "\n";
			}
			else if (key.compare("DATA_RATE") == 0)
			{
				std::string v;
				conf >> v;
				data_rate = v;
				std::cerr << "DATA_RATE\t\t\t" << data_rate << "\n";
			}
			else if (key.compare("LINK_DELAY") == 0)
			{
				std::string v;
				conf >> v;
				link_delay = v;
				std::cerr << "LINK_DELAY\t\t\t" << link_delay << "\n";
			}
			else if (key.compare("PACKET_PAYLOAD_SIZE") == 0)
			{
				uint32_t v;
				conf >> v;
				packet_payload_size = v;
				std::cerr << "PACKET_PAYLOAD_SIZE\t\t" << packet_payload_size << "\n";
			}
			else if (key.compare("L2_CHUNK_SIZE") == 0)
			{
				uint32_t v;
				conf >> v;
				l2_chunk_size = v;
				std::cerr << "L2_CHUNK_SIZE\t\t\t" << l2_chunk_size << "\n";
			}
			else if (key.compare("L2_ACK_INTERVAL") == 0)
			{
				uint32_t v;
				conf >> v;
				l2_ack_interval = v;
				std::cerr << "L2_ACK_INTERVAL\t\t\t" << l2_ack_interval << "\n";
			}
			else if (key.compare("L2_BACK_TO_ZERO") == 0)
			{
				uint32_t v;
				conf >> v;
				l2_back_to_zero = v;
				if (l2_back_to_zero)
					std::cerr << "L2_BACK_TO_ZERO\t\t\t" << "Yes" << "\n";
				else
					std::cerr << "L2_BACK_TO_ZERO\t\t\t" << "No" << "\n";
			}
			else if (key.compare("TOPOLOGY_FILE") == 0)
			{
				std::string v;
				conf >> v;
				topology_file = v;
				std::cerr << "TOPOLOGY_FILE\t\t\t" << topology_file << "\n";
			}
			else if (key.compare("FLOW_FILE") == 0)
			{
				std::string v;
				conf >> v;
				flow_file = v;
				std::cerr << "FLOW_FILE\t\t\t" << flow_file << "\n";
			}
			else if (key.compare("TRACE_FILE") == 0)
			{
				std::string v;
				conf >> v;
				trace_file = v;
				std::cerr << "TRACE_FILE\t\t\t" << trace_file << "\n";
			}
			else if (key.compare("TRACE_OUTPUT_FILE") == 0)
			{
				std::string v;
				conf >> v;
				trace_output_file = v;
				if (argc > 2)
				{
					trace_output_file = trace_output_file + std::string(argv[2]);
				}
				std::cerr << "TRACE_OUTPUT_FILE\t\t" << trace_output_file << "\n";
			}
			else if (key.compare("SIMULATOR_STOP_TIME") == 0)
			{
				double v;
				conf >> v;
				simulator_stop_time = v;
				std::cerr << "SIMULATOR_STOP_TIME\t\t" << simulator_stop_time << "\n";
			}
			else if (key.compare("ALPHA_RESUME_INTERVAL") == 0)
			{
				double v;
				conf >> v;
				alpha_resume_interval = v;
				std::cerr << "ALPHA_RESUME_INTERVAL\t\t" << alpha_resume_interval << "\n";
			}
			else if (key.compare("RP_TIMER") == 0)
			{
				double v;
				conf >> v;
				rp_timer = v;
				std::cerr << "RP_TIMER\t\t\t" << rp_timer << "\n";
			}
			else if (key.compare("EWMA_GAIN") == 0)
			{
				double v;
				conf >> v;
				ewma_gain = v;
				std::cerr << "EWMA_GAIN\t\t\t" << ewma_gain << "\n";
			}
			else if (key.compare("FAST_RECOVERY_TIMES") == 0)
			{
				uint32_t v;
				conf >> v;
				fast_recovery_times = v;
				std::cerr << "FAST_RECOVERY_TIMES\t\t" << fast_recovery_times << "\n";
			}
			else if (key.compare("RATE_AI") == 0)
			{
				std::string v;
				conf >> v;
				rate_ai = v;
				std::cerr << "RATE_AI\t\t\t\t" << rate_ai << "\n";
			}
			else if (key.compare("RATE_HAI") == 0)
			{
				std::string v;
				conf >> v;
				rate_hai = v;
				std::cerr << "RATE_HAI\t\t\t" << rate_hai << "\n";
			}
			else if (key.compare("ERROR_RATE_PER_LINK") == 0)
			{
				double v;
				conf >> v;
				error_rate_per_link = v;
				std::cerr << "ERROR_RATE_PER_LINK\t\t" << error_rate_per_link << "\n";
			}
			else if (key.compare("CC_MODE") == 0){
				conf >> cc_mode;
				std::cerr << "CC_MODE\t\t" << cc_mode << '\n';
			}else if (key.compare("RATE_DECREASE_INTERVAL") == 0){
				double v;
				conf >> v;
				rate_decrease_interval = v;
				std::cerr << "RATE_DECREASE_INTERVAL\t\t" << rate_decrease_interval << "\n";
			}else if (key.compare("MIN_RATE") == 0){
				conf >> min_rate;
				std::cerr << "MIN_RATE\t\t" << min_rate << "\n";
			}else if (key.compare("FCT_OUTPUT_FILE") == 0){
				conf >> fct_output_file;
				std::cerr << "FCT_OUTPUT_FILE\t\t" << fct_output_file << '\n';
			}else if (key.compare("HAS_WIN") == 0){
				conf >> has_win;
				std::cerr << "HAS_WIN\t\t" << has_win << "\n";
			}else if (key.compare("GLOBAL_T") == 0){
				conf >> global_t;
				std::cerr << "GLOBAL_T\t\t" << global_t << '\n';
			}else if (key.compare("MI_THRESH") == 0){
				conf >> mi_thresh;
				std::cerr << "MI_THRESH\t\t" << mi_thresh << '\n';
			}else if (key.compare("VAR_WIN") == 0){
				uint32_t v;
				conf >> v;
				var_win = v;
				std::cerr << "VAR_WIN\t\t" << v << '\n';
			}else if (key.compare("FAST_REACT") == 0){
				uint32_t v;
				conf >> v;
				fast_react = v;
				std::cerr << "FAST_REACT\t\t" << v << '\n';
			}else if (key.compare("U_TARGET") == 0){
				conf >> u_target;
				std::cerr << "U_TARGET\t\t" << u_target << '\n';
			}else if (key.compare("INT_MULTI") == 0){
				conf >> int_multi;
				std::cerr << "INT_MULTI\t\t\t\t" << int_multi << '\n';
			}else if (key.compare("RATE_BOUND") == 0){
				uint32_t v;
				conf >> v;
				rate_bound = v;
				std::cerr << "RATE_BOUND\t\t" << rate_bound << '\n';
			}else if (key.compare("ACK_HIGH_PRIO") == 0){
				conf >> ack_high_prio;
				std::cerr << "ACK_HIGH_PRIO\t\t" << ack_high_prio << '\n';
			}else if (key.compare("DCTCP_RATE_AI") == 0){
				conf >> dctcp_rate_ai;
				std::cerr << "DCTCP_RATE_AI\t\t\t\t" << dctcp_rate_ai << "\n";
			}else if (key.compare("PFC_OUTPUT_FILE") == 0){
				conf >> pfc_output_file;
				std::cerr << "PFC_OUTPUT_FILE\t\t\t\t" << pfc_output_file << '\n';
			}else if (key.compare("LINK_DOWN") == 0){
				conf >> link_down_time >> link_down_A >> link_down_B;
				std::cerr << "LINK_DOWN\t\t\t\t" << link_down_time << ' '<< link_down_A << ' ' << link_down_B << '\n';
			}else if (key.compare("ENABLE_TRACE") == 0){
				conf >> enable_trace;
				std::cerr << "ENABLE_TRACE\t\t\t\t" << enable_trace << '\n';
			}else if (key.compare("KMAX_MAP") == 0){
				int n_k ;
				conf >> n_k;
				std::cerr << "KMAX_MAP\t\t\t\t";
				for (int i = 0; i < n_k; i++){
					uint64_t rate;
					uint32_t k;
					conf >> rate >> k;
					rate2kmax[rate] = k;
					std::cerr << ' ' << rate << ' ' << k;
				}
				std::cerr<<'\n';
			}else if (key.compare("KMIN_MAP") == 0){
				int n_k ;
				conf >> n_k;
				std::cerr << "KMIN_MAP\t\t\t\t";
				for (int i = 0; i < n_k; i++){
					uint64_t rate;
					uint32_t k;
					conf >> rate >> k;
					rate2kmin[rate] = k;
					std::cerr << ' ' << rate << ' ' << k;
				}
				std::cerr<<'\n';
			}else if (key.compare("PMAX_MAP") == 0){
				int n_k ;
				conf >> n_k;
				std::cerr << "PMAX_MAP\t\t\t\t";
				for (int i = 0; i < n_k; i++){
					uint64_t rate;
					double p;
					conf >> rate >> p;
					rate2pmax[rate] = p;
					std::cerr << ' ' << rate << ' ' << p;
				}
				std::cerr<<'\n';
			}else if (key.compare("BUFFER_SIZE") == 0){
				conf >> buffer_size;
				std::cerr << "BUFFER_SIZE\t\t\t\t" << buffer_size << '\n';
			}else if (key.compare("QLEN_MON_FILE") == 0){
				conf >> qlen_mon_file;
				std::cerr << "QLEN_MON_FILE\t\t\t\t" << qlen_mon_file << '\n';
			}else if (key.compare("QLEN_MON_START") == 0){
				conf >> qlen_mon_start;
				std::cerr << "QLEN_MON_START\t\t\t\t" << qlen_mon_start << '\n';
			}else if (key.compare("QLEN_MON_END") == 0){
				conf >> qlen_mon_end;
				std::cerr << "QLEN_MON_END\t\t\t\t" << qlen_mon_end << '\n';
			}else if (key.compare("MULTI_RATE") == 0){
				int v;
				conf >> v;
				multi_rate = v;
				std::cerr << "MULTI_RATE\t\t\t\t" << multi_rate << '\n';
			}else if (key.compare("SAMPLE_FEEDBACK") == 0){
				int v;
				conf >> v;
				sample_feedback = v;
				std::cerr << "SAMPLE_FEEDBACK\t\t\t\t" << sample_feedback << '\n';
            // Added From Here
			}else if (key.compare("HPCC_WORKLOAD") == 0 || key.compare("TCP_FLOW_FILE") == 0){
				std::string v;
				conf >> v;
				hpcc_workload = v;
				std::cerr << "HPCC_WORKLOAD(TCP_FLOW_FILE)\t\t" << hpcc_workload << '\n';
			} else if (key.compare("LOAD") == 0) {
				double v;
				conf >> v;
				load = v;
				std::cerr << "LOAD\t\t\t" << load << "\n";
			} else if (key.compare("FOREGROUND_RATIO") == 0) {
				double v;
				conf >> v;
				foreground_flow_ratio = v;
				std::cerr << "FOREGROUND_RATIO\t\t" << foreground_flow_ratio << "\n";
			} else if (key.compare("APP_START_TIME") == 0) {
				double v;
				conf >> v;
				app_start_time = v;
				std::cerr << "APP_START_TIME\t\t\t" << app_start_time << "\n";
			} else if (key.compare("APP_STOP_TIME") == 0) {
				double v;
				conf >> v;
				app_stop_time = v;
				std::cerr << "APP_STOP_TIME\t\t\t" << app_stop_time << "\n";
			} else if (key.compare("DCTCP_INCAST_SIZE") == 0 || key.compare("INCAST_FLOW_SIZE") == 0) {
				double v;
				conf >> v;
				incast_flow_size = v;
				std::cerr << "INCAST_FLOW_SIZE(DCTCP_INCAST_SIZE)\t\t" << incast_flow_size << "\n";
            }else if (key.compare("NUM_BG_FLOWS") == 0 || key.compare("TCP_FLOW_TOTAL") == 0){
				int v;
				conf >> v;
				num_bg_flows = v;
				std::cerr << "NUM_BG_FLOWS(TCP_FLOW_TOTAL)\t\t\t\t" << num_bg_flows << '\n';
            } else if (key.compare("ENABLE_IRN") == 0) {
				bool v;
				conf >> v;
				enable_irn = v;
				std::cerr << "ENABLE_IRN\t\t" << enable_irn << "\n";
            } else if (key.compare("ENABLE_TLT") == 0) {
				bool v;
				conf >> v;
				enable_tlt = v;
				std::cerr << "ENABLE_TLT\t\t" << enable_tlt << "\n";
			} else if (key.compare("IRN_NO_BDPFC") == 0) {
				bool v;
				conf >> v;
				irn_no_bdpfc = v;
				std::cerr << "IRN_NO_BDPFC\t\t" << irn_no_bdpfc << "\n";
			} else if (key.compare("TLT_MAXBYTES_UIP") == 0) {
				double v;
				conf >> v;
				tlt_maxbytes_uip = v;
				std::cerr << "TLT_MAXBYTES_UIP\t\t" << tlt_maxbytes_uip << "\n";
			} else if (key.compare("DUMBBELL_NUMHOST") == 0) {
				int v;
				conf >> v;
				dumbbell_numhost = v;
				std::cerr << "DUMBBELL_NUMHOST\t\t\t\t" << dumbbell_numhost << '\n';
			} else if (key.compare("DUMBBELL_NUMFLOWPERHOST") == 0) {
				int v;
				conf >> v;
				dumbbell_numflowperhost = v;
				std::cerr << "DUMBBELL_NUMFLOWPERHOST\t\t\t\t" << dumbbell_numflowperhost << '\n';
			} else if (key.compare("DUMBBELL_FLOWSIZE") == 0) {
				int v;
				conf >> v;
				dumbbell_flowsize = v;
				std::cerr << "DUMBBELL_FLOWSIZE\t\t\t\t" << dumbbell_flowsize << '\n';
			} else if (key.compare("DUMBBELL_LINKCAP") == 0) {
				std::string v;
				conf >> v;
				dumbbell_linkcap = v;
				std::cerr << "DUMBBELL_LINKCAP\t\t\t\t" << dumbbell_linkcap << '\n';
			}

			fflush(stdout);
		}
		conf.close();
        
		if(!load_workload(hpcc_workload.c_str(), &workload_cdf)){
			std::cerr<< "Failed to open workload file " << hpcc_workload.c_str() << std::endl;
			return 1;
		}
	}
	else
	{
		std::cerr << "Error: require a config file\n";
		fflush(stdout);
		return 1;
	}


	bool dynamicth = use_dynamic_pfc_threshold;

	Config::SetDefault("ns3::QbbNetDevice::PauseTime", UintegerValue(pause_time));
	Config::SetDefault("ns3::QbbNetDevice::QcnEnabled", BooleanValue(enable_qcn));
	Config::SetDefault("ns3::QbbNetDevice::DynamicThreshold", BooleanValue(dynamicth));
	Config::SetDefault("ns3::QbbNetDevice::QbbEnabled", BooleanValue(enable_pfc));

	// set int_multi
	IntHop::multi = int_multi;
	// IntHeader::mode
	if (cc_mode == 7) // timely, use ts
		IntHeader::mode = 1;
	else if (cc_mode == 3) // hpcc, use int
		IntHeader::mode = 0;
	else // others, no extra header
		IntHeader::mode = 5;

	SeedManager::SetSeed(5);


	std::ifstream tracef; //std::ifstream topof, flowf, tracef;
	//topof.open(topology_file.c_str());
	// flowf.open(flow_file.c_str());
	tracef.open(trace_file.c_str());
	uint32_t trace_num; // uint32_t node_num, switch_num, link_num, flow_num, trace_num;
	// topof >> node_num >> switch_num >> link_num;
	// flowf >> flow_num;
	uint32_t node_num = (dumbbell_numhost + 1) * 2;
	tracef >> trace_num;

	NodeContainer n;
	//n.Create(node_num);
	std::vector<uint32_t> node_type(node_num, 0);
	for (uint32_t i = 0; i < 2; i++)
	{
		node_type[i] = 1;
	}
	for (uint32_t i = 0; i < node_num; i++){
		if (node_type[i] == 0)
			n.Add(CreateObject<Node>());
		else{
			Ptr<SwitchNode> sw = CreateObject<SwitchNode>();
			n.Add(sw);
			sw->SetAttribute("EcnEnabled", BooleanValue(enable_qcn));
		}
	}


	NS_LOG_INFO("Create nodes.");

	InternetStackHelper internet;
	internet.Install(n);

	//
	// Assign IP to each server
	//
	std::vector<Ipv4Address> serverAddress;
	for (uint32_t i = 0; i < node_num; i++){
		if (n.Get(i)->GetNodeType() == 0){ // is server
			serverAddress.resize(i + 1);
			serverAddress[i] = Ipv4Address(0x0b000001 + ((i / 256) * 0x00010000) + ((i % 256) * 0x00000100));
		}
	}

	NS_LOG_INFO("Create channels.");

	//
	// Explicitly create the channels required by the topology.
	//

	Ptr<RateErrorModel> rem = CreateObject<RateErrorModel>();
	Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
	rem->SetRandomVariable(uv);
	uv->SetStream(50);
	rem->SetAttribute("ErrorRate", DoubleValue(error_rate_per_link));
	rem->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));

	FILE *pfc_file = fopen(pfc_output_file.c_str(), "w");

	QbbHelper qbb;
	Ipv4AddressHelper ipv4;
	for (uint32_t i = 0; i <= 2*dumbbell_numhost; i++)
	{
		uint32_t src, dst;
		std::string data_rate, link_delay = "0.001ms";
		double error_rate;
		
		if (i == 0) {
			src = 0;
			dst = 1;
		}
		else
		{
			if (i % 2) {
				src = i+1;
				dst = 0;
			}
			else
			{
				src = i+1;
				dst = 1;
			}
		}

		data_rate = dumbbell_linkcap;
		error_rate = dumbbell_errorrate;
		
		Ptr<Node> snode = n.Get(src), dnode = n.Get(dst);

		qbb.SetDeviceAttribute("DataRate", StringValue(data_rate));
		qbb.SetChannelAttribute("Delay", StringValue(link_delay));

		if (error_rate > 0)
		{
			Ptr<RateErrorModel> rem = CreateObject<RateErrorModel>();
			Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
			rem->SetRandomVariable(uv);
			uv->SetStream(50);
			rem->SetAttribute("ErrorRate", DoubleValue(error_rate));
			rem->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
			qbb.SetDeviceAttribute("ReceiveErrorModel", PointerValue(rem));
		}
		else
		{
			qbb.SetDeviceAttribute("ReceiveErrorModel", PointerValue(rem));
		}

		fflush(stdout);

		// Assigne server IP
		// Note: this should be before the automatic assignment below (ipv4.Assign(d)),
		// because we want our IP to be the primary IP (first in the IP address list),
		// so that the global routing is based on our IP
		NetDeviceContainer d = qbb.Install(snode, dnode);
		if (snode->GetNodeType() == 0){
			Ptr<Ipv4> ipv4 = snode->GetObject<Ipv4>();
			ipv4->AddInterface(d.Get(0));
			ipv4->AddAddress(1, Ipv4InterfaceAddress(serverAddress[src], Ipv4Mask(0xff000000)));
		}
		if (dnode->GetNodeType() == 0){
			Ptr<Ipv4> ipv4 = dnode->GetObject<Ipv4>();
			ipv4->AddInterface(d.Get(1));
			ipv4->AddAddress(1, Ipv4InterfaceAddress(serverAddress[dst], Ipv4Mask(0xff000000)));
		}

		// used to create a graph of the topology
		nbr2if[snode][dnode].idx = DynamicCast<QbbNetDevice>(d.Get(0))->GetIfIndex();
		nbr2if[snode][dnode].up = true;
		nbr2if[snode][dnode].delay = DynamicCast<QbbChannel>(DynamicCast<QbbNetDevice>(d.Get(0))->GetChannel())->GetDelay().GetTimeStep();
		nbr2if[snode][dnode].bw = DynamicCast<QbbNetDevice>(d.Get(0))->GetDataRate().GetBitRate();
		nbr2if[dnode][snode].idx = DynamicCast<QbbNetDevice>(d.Get(1))->GetIfIndex();
		nbr2if[dnode][snode].up = true;
		nbr2if[dnode][snode].delay = DynamicCast<QbbChannel>(DynamicCast<QbbNetDevice>(d.Get(1))->GetChannel())->GetDelay().GetTimeStep();
		nbr2if[dnode][snode].bw = DynamicCast<QbbNetDevice>(d.Get(1))->GetDataRate().GetBitRate();

		// This is just to set up the connectivity between nodes. The IP addresses are useless
		char ipstring[16];
		sprintf(ipstring, "10.%d.%d.0", i / 254 + 1, i % 254 + 1);
		ipv4.SetBase(ipstring, "255.255.255.0");
		ipv4.Assign(d);

		// setup PFC trace
		DynamicCast<QbbNetDevice>(d.Get(0))->TraceConnectWithoutContext("QbbPfc", MakeBoundCallback (&get_pfc, pfc_file, DynamicCast<QbbNetDevice>(d.Get(0))));
		DynamicCast<QbbNetDevice>(d.Get(1))->TraceConnectWithoutContext("QbbPfc", MakeBoundCallback (&get_pfc, pfc_file, DynamicCast<QbbNetDevice>(d.Get(1))));
	}

	nic_rate = get_nic_rate(n);

	// config switch
	for (uint32_t i = 0; i < node_num; i++){
		if (n.Get(i)->GetNodeType() == 1){ // is switch
			Ptr<SwitchNode> sw = DynamicCast<SwitchNode>(n.Get(i));
			uint32_t shift = 3; // by default 1/8
			for (uint32_t j = 1; j < sw->GetNDevices(); j++){
				Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(sw->GetDevice(j));
				// set ecn
				uint64_t rate = dev->GetDataRate().GetBitRate();
				NS_ASSERT_MSG(rate2kmin.find(rate) != rate2kmin.end(), "must set kmin for each link speed");
				NS_ASSERT_MSG(rate2kmax.find(rate) != rate2kmax.end(), "must set kmax for each link speed");
				NS_ASSERT_MSG(rate2pmax.find(rate) != rate2pmax.end(), "must set pmax for each link speed");
				sw->m_mmu->ConfigEcn(j, rate2kmin[rate], rate2kmax[rate], rate2pmax[rate]);
				// set pfc
				uint64_t delay = DynamicCast<QbbChannel>(dev->GetChannel())->GetDelay().GetTimeStep();
				uint32_t headroom = rate * delay / 8 / 1000000000 * 2 + 2 * sw->m_mmu->MTU;
				sw->m_mmu->ConfigHdrm(j, headroom);
			}
			sw->m_mmu->ConfigNPort(sw->GetNDevices()-1);
			sw->m_mmu->ConfigBufferSize(buffer_size* 1024 * 1024);
			sw->m_mmu->node_id = sw->GetId();
			sw->m_mmu->SetAttribute("MaxBytesTltUip", DoubleValue(enable_tlt ? tlt_maxbytes_uip : 0));
			sw->m_mmu->SetAttribute("TltEnable", BooleanValue(enable_tlt));
			fprintf(stderr, "Node %u : Broadcom switch (%u ports / %gMB MMU)\n", i, sw->GetNDevices() - 1, sw->m_mmu->GetMmuBufferBytes() / 1000000.);
		}
	}

	#if ENABLE_QP
	FILE *fct_output = fopen(fct_output_file.c_str(), "w");
	//
	// install RDMA driver
	//
	for (uint32_t i = 0; i < node_num; i++){
		if (n.Get(i)->GetNodeType() == 0){ // is server
			// create RdmaHw
			Ptr<RdmaHw> rdmaHw = CreateObject<RdmaHw>();
			rdmaHw->SetAttribute("ClampTargetRate", BooleanValue(clamp_target_rate));
			rdmaHw->SetAttribute("AlphaResumInterval", DoubleValue(alpha_resume_interval));
			rdmaHw->SetAttribute("RPTimer", DoubleValue(rp_timer));
			rdmaHw->SetAttribute("FastRecoveryTimes", UintegerValue(fast_recovery_times));
			rdmaHw->SetAttribute("EwmaGain", DoubleValue(ewma_gain));
			rdmaHw->SetAttribute("RateAI", DataRateValue(DataRate(rate_ai)));
			rdmaHw->SetAttribute("RateHAI", DataRateValue(DataRate(rate_hai)));
			rdmaHw->SetAttribute("L2BackToZero", BooleanValue(l2_back_to_zero));
			rdmaHw->SetAttribute("L2ChunkSize", UintegerValue(l2_chunk_size));
			rdmaHw->SetAttribute("L2AckInterval", UintegerValue(l2_ack_interval));
			rdmaHw->SetAttribute("CcMode", UintegerValue(cc_mode));
			rdmaHw->SetAttribute("RateDecreaseInterval", DoubleValue(rate_decrease_interval));
			rdmaHw->SetAttribute("MinRate", DataRateValue(DataRate(min_rate)));
			rdmaHw->SetAttribute("Mtu", UintegerValue(packet_payload_size));
			rdmaHw->SetAttribute("MiThresh", UintegerValue(mi_thresh));
			rdmaHw->SetAttribute("VarWin", BooleanValue(var_win));
			rdmaHw->SetAttribute("FastReact", BooleanValue(fast_react));
			rdmaHw->SetAttribute("MultiRate", BooleanValue(multi_rate));
			rdmaHw->SetAttribute("SampleFeedback", BooleanValue(sample_feedback));
			rdmaHw->SetAttribute("TargetUtil", DoubleValue(u_target));
			rdmaHw->SetAttribute("RateBound", BooleanValue(rate_bound));
			rdmaHw->SetAttribute("DctcpRateAI", DataRateValue(DataRate(dctcp_rate_ai)));
			rdmaHw->SetAttribute("IrnEnable", BooleanValue(enable_irn));
			if (enable_irn && (cc_mode == 3 || irn_no_bdpfc)) {
				rdmaHw->SetAttribute("IrnRtoHigh", TimeValue(MicroSeconds(4000)));
				rdmaHw->SetAttribute("IrnRtoLow", TimeValue(MicroSeconds(4000)));
				rdmaHw->SetAttribute("IrnBdp", UintegerValue(100000000));  // 3us * 50Gbps
			} else {
				rdmaHw->SetAttribute("IrnRtoHigh", TimeValue(MicroSeconds(1930)));
				rdmaHw->SetAttribute("IrnRtoLow", TimeValue(MicroSeconds(454)));
				rdmaHw->SetAttribute("IrnBdp", UintegerValue(18750));  // 3us * 50Gbps
			}
			rdmaHw->SetAttribute("TltEnable", BooleanValue(enable_tlt));

			Simulator::Schedule(Seconds(simulator_stop_time-0.01), &RdmaHw::PrintStat, rdmaHw);

			// create and install RdmaDriver
			Ptr<RdmaDriver> rdma = CreateObject<RdmaDriver>();
			Ptr<Node> node = n.Get(i);
			rdma->SetNode(node);
			rdma->SetRdmaHw(rdmaHw);

			node->AggregateObject (rdma);
			rdma->Init();
			rdma->TraceConnectWithoutContext("QpComplete", MakeBoundCallback (qp_finish, fct_output));
		}
	}
	#endif

	// set ACK priority on hosts
	if (ack_high_prio)
		RdmaEgressQueue::ack_q_idx = 0;
	else
		RdmaEgressQueue::ack_q_idx = 3;

	//
	// setup switch CC
	//
	for (uint32_t i = 0; i < node_num; i++){
		if (n.Get(i)->GetNodeType() == 1){ // switch
			Ptr<SwitchNode> sw = DynamicCast<SwitchNode>(n.Get(i));
			sw->SetAttribute("CcMode", UintegerValue(cc_mode));
		}
	}

	// setup routing
	CalculateRoutes(n);
	SetRoutingEntries();

	//
	// get BDP and delay
	//
	maxRtt = maxBdp = 0;
	for (uint32_t i = 0; i < node_num; i++){
		if (n.Get(i)->GetNodeType() != 0)
			continue;
		for (uint32_t j = i+1; j < node_num; j++){
			if (n.Get(j)->GetNodeType() != 0)
				continue;
			uint64_t delay = pairDelay[n.Get(i)][n.Get(j)];
			uint64_t txDelay = pairTxDelay[n.Get(i)][n.Get(j)];
			uint64_t rtt = delay * 2 + txDelay;
			uint64_t bw = pairBw[n.Get(i)][n.Get(j)];
			uint64_t bdp = rtt * bw / 1000000000/8; 
			pairBdp[n.Get(i)][n.Get(j)] = bdp;
			pairRtt[n.Get(i)][n.Get(j)] = rtt;
			if (bdp > maxBdp)
				maxBdp = bdp;
			if (rtt > maxRtt)
				maxRtt = rtt;
		}
	}
	fprintf(stderr, "maxRtt: %lu, maxBdp: %lu\n", maxRtt, maxBdp);

	//
	// add trace
	//

	NodeContainer trace_nodes;
	for (uint32_t i = 0; i < trace_num; i++)
	{
		uint32_t nid;
		tracef >> nid;
		if (nid >= n.GetN()){
			continue;
		}
		trace_nodes = NodeContainer(trace_nodes, n.Get(nid));
	}

	FILE *trace_output = fopen(trace_output_file.c_str(), "w");
	if (enable_trace)
		qbb.EnableTracing(trace_output, trace_nodes);
    if (!trace_output)
        perror("fopen");
	// dump link speed to trace file
	{
		SimSetting sim_setting;
		for (auto i: nbr2if){
			for (auto j : i.second){
				uint16_t node = i.first->GetId();
				uint8_t intf = j.second.idx;
				uint64_t bps = DynamicCast<QbbNetDevice>(i.first->GetDevice(j.second.idx))->GetDataRate().GetBitRate();
				sim_setting.port_speed[node][intf] = bps;
			}
		}
		sim_setting.win = maxBdp;
		sim_setting.Serialize(trace_output);
	}

	Ipv4GlobalRoutingHelper::PopulateRoutingTables();

	NS_LOG_INFO("Create Applications.");

	uint32_t packetSize = packet_payload_size;
	Time interPacketInterval = Seconds(0.0000005 / 2);

    Ptr<ExponentialRandomVariable> exp_rv = CreateObject<ExponentialRandomVariable> ();
	Ptr<UniformRandomVariable> uniform_rv = CreateObject<UniformRandomVariable> ();
	exp_rv->SetStream(0); // deterministic
	uniform_rv->SetStream(0); // deterministic

	uint32_t MTU_SIZE = packetSize+48; // Updated to fit RDMA
	uint32_t MSS_SIZE = packetSize; // Updated to fit RDMA
	
	int host_num = node_num - 2;
	double current_time = app_start_time+0.01;
	std::vector<Ptr<UdpServer>> udp_servers;
	uint32_t flow_id = 0;
	std::unordered_map<uint32_t, uint32_t> flows_per_host;
	// uint16_t port_num = 10000;
	uint16_t* port_per_host = new uint16_t[host_num];

	// maintain port number for each host
	std::unordered_map<uint32_t, uint16_t> portNumder;
	std::unordered_map<uint32_t, uint16_t> dportNumder;
	for (uint32_t i = 0; i < node_num; i++){
		if (n.Get(i)->GetNodeType() == 0) {
			portNumder[i] = 10000; // each host use port number from 10000
			dportNumder[i] = 100;
		}
	}

	for (uint32_t send_host = 0; send_host < node_num -2 ; send_host += 2)
	{
		
		for (uint32_t i = 0; i < dumbbell_numflowperhost; i++)
		{
			uint32_t recv_host, src, dst, maxPacketCount, port;
			recv_host = send_host + 1;

			src = send_host + 2;
			dst = recv_host + 2;

			if (!MAP_KEY_EXISTS(flows_per_host, src))
				flows_per_host[src] = 0;
			flows_per_host[src]++;
			if (!MAP_KEY_EXISTS(flows_per_host, dst))
				flows_per_host[dst] = 0;
			flows_per_host[dst]++;

			port = port_per_host[send_host]++;

			uint32_t target_len = dumbbell_flowsize;
			if (target_len == 0)
				target_len = 1;

			maxPacketCount = (target_len + MSS_SIZE - 1) / MSS_SIZE;

			NS_ASSERT(n.Get(src)->GetNodeType() == 0 && n.Get(dst)->GetNodeType() == 0);
			// Ptr<Ipv4> ipv4 = n.Get(dst)->GetObject<Ipv4>();
			// Ipv4Address serverAddress = ipv4->GetAddress(1, 0).GetLocal(); //GetAddress(0,0) is the loopback 127.0.0.1

			uint32_t flow_size = target_len;
			maxPacketCount = (flow_size + MSS_SIZE - 1) / MSS_SIZE;

			int pg = 3;
			int dport = dportNumder[dst];
			dportNumder[dst] = dportNumder[dst] + 1;
			UdpServerHelper server0(port);
			server0.SetAttribute("FlowSize",UintegerValue(flow_size));
			server0.SetAttribute("irn", BooleanValue(enable_irn));
			server0.SetAttribute("StatHostSrc", UintegerValue(src));
			server0.SetAttribute("StatHostDst", UintegerValue(dst));
			server0.SetAttribute("StatRxLen", UintegerValue(flow_size));
			server0.SetAttribute("StatFlowID", UintegerValue(flow_id));
			server0.SetAttribute("Port", UintegerValue(dport));

			ApplicationContainer apps0s = server0.Install(n.Get(dst));
			apps0s.Start(Seconds(app_start_time));
			apps0s.Stop(Seconds(app_stop_time));
			// udp_servers.push_back(DynamicCast<UdpServer, Application>(apps0s.Get(0)));

			NS_ASSERT(n.Get(src)->GetNodeType() == 0 && n.Get(dst)->GetNodeType() == 0);
			port = portNumder[src]++; // get a new port number
			RdmaClientHelper clientHelper(pg, serverAddress[src], serverAddress[dst], port, dport, target_len, has_win ? (global_t == 1 ? maxBdp : pairBdp[n.Get(src)][n.Get(dst)]) : 0, global_t == 1 ? maxRtt : pairRtt[n.Get(src)][n.Get(dst)]);
			// clientHelper.SetAttribute("MaxPackets", UintegerValue(maxPacketCount));
			// clientHelper.SetAttribute("Interval", TimeValue(interPacketInterval));
			// clientHelper.SetAttribute("PacketSize", UintegerValue(packetSize+12)); // Important! Include SeqTsHeader
			// clientHelper.SetAttribute("FlowSize", UintegerValue(flow_size));
			clientHelper.SetAttribute("StatFlowID", IntegerValue(flow_id));

			ApplicationContainer appCon = clientHelper.Install(n.Get(src));
			appCon.Start(Seconds(current_time));
			appCon.Stop(Seconds(app_stop_time));

			std::cerr << "Flow " << flow_id++ << " : Total length : " << flow_size << "(Total " << maxPacketCount << " Packets) at " << current_time << std::endl;

			// current_time += exp_rv->GetValue();
		}

	}
	for(auto iter=flows_per_host.begin(); iter != flows_per_host.end(); ++iter) {
		std::cerr << "Host " << iter->first << " : Expected " << iter->second << " flows" << std::endl;
	}

	qbb.EnableAsciiAll("qbbcap");

	// topof.close();
	// flowf.close();
	tracef.close();

	// schedule link down
	if (link_down_time > 0){
		Simulator::Schedule(Seconds(2) + MicroSeconds(link_down_time), &TakeDownLink, n, n.Get(link_down_A), n.Get(link_down_B));
	}

	// schedule buffer monitor
	FILE* qlen_output = fopen(qlen_mon_file.c_str(), "w");
	Simulator::Schedule(NanoSeconds(qlen_mon_start), &monitor_buffer, qlen_output, &n);

	//
	// Now, do the actual simulation.
	//
	std::cerr << "Running Simulation.\n";
	fflush(stdout);
	NS_LOG_INFO("Run Simulation.");
	Simulator::Stop(Seconds(simulator_stop_time));
	Simulator::Run();
	Simulator::Destroy();
	NS_LOG_INFO("Done.");
	fclose(trace_output);

	endt = clock();
	std::cerr << (double)(endt - begint) / CLOCKS_PER_SEC << "\n";

}


bool load_workload(const char *workload_file, uint32_t **workload_cdf) {
  FILE *f = fopen(workload_file, "r");
  if(!f) return false;
  *workload_cdf = new uint32_t[1001];
  int flow_size;
  double value, prev_fs = 0.;
  int cursor = 0;
  while(fscanf(f, "%d %lf", &flow_size, &value) == 2) {
    int current = (int)(value*1000.);
    for(int i=cursor; i < current; i++) {
      (*workload_cdf)[i] = prev_fs + (flow_size-prev_fs)*(i-cursor)/((double)(current-cursor));
    }
    cursor = current;
    prev_fs = flow_size;
  }
  for (int i=cursor; i< 1001; i++){
    (*workload_cdf)[i] = flow_size;
  }
  fclose(f);
  return true;
}