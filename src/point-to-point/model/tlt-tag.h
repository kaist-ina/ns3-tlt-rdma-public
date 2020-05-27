/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
* Author: Hwijoon Lim <wjuni@kaist.ac.kr>
*/
#ifndef TLT_TAG_H
#define TLT_TAG_H

#include "ns3/tag.h"

namespace ns3 {
	/**
	* \ingroup tlt
	* \brief The packet header for an TLT packet
	*/
	class TltTag : public Tag
	{
	public:
		TltTag();
		static TypeId GetTypeId(void);
		virtual TypeId GetInstanceTypeId(void) const;
		virtual void Print(std::ostream &os) const;
		virtual uint32_t GetSerializedSize(void) const;
		virtual void Serialize(TagBuffer i) const;
		virtual void Deserialize(TagBuffer i);
		void SetType(uint8_t ttl);
		uint8_t GetType();
		void SetControlType(uint8_t ttl);
		uint8_t GetControlType();
		int32_t debug_socketId {-1};

		enum TltType_e {
			PACKET_IMPORTANT_CONTROL = 6,
			PACKET_IMPORTANT_FAST_RETRANS = 5,
			PACKET_IMPORTANT_ECHO_FORCE = 4,
			PACKET_IMPORTANT_FORCE = 3,
			PACKET_IMPORTANT_ECHO = 2,
			PACKET_IMPORTANT = 1,
			PACKET_NOT_IMPORTANT = 0
		};

		enum ControlType_e {
			PACKET_PAYLOAD_PERIODIC = 10,
			PACKET_NACK_ECHO = 9,
			PACKET_PAYLOAD_IRN_FR = 8,
			PACKET_PAYLOAD_IRN = 7,
			PACKET_PAYLOAD_RETX = 6,
			PACKET_PAYLOAD_EOF = 5,
			PACKET_CNP = 4,
			PACKET_NACK = 3,
			PACKET_ACK = 2,
			PACKET_PAYLOAD = 1,
			PACKET_NONE = 0
		};
	private:
		uint8_t m_type;
		uint8_t m_control_type;
	};

} // namespace ns3

#endif /* TLT_TAG_H */