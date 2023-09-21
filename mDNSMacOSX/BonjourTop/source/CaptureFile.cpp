//
//  CaptureFile.cpp
//  TestTB
//
//  Created by Terrin Eager on 9/14/12.
//
//

#include "CaptureFile.h"
#include <stdio.h>
#include <pcap.h>
#include <pcap/pcap-ng.h>
#include <sys/types.h>

#define BJ_MAX_PACKET (1024*20)

struct packetheader
{
    __uint32_t sec;
    __uint32_t usec;
    __uint32_t captureLen;
    __uint32_t origLen;

};


CCaptureFile::CCaptureFile()
{
    m_pFrameData = NULL;
    m_hPCap = NULL;

    m_nFirstFrameTime = 0;

    if (!Init())
        Clear();
}
CCaptureFile::~CCaptureFile()
{
    Clear();
}

bool CCaptureFile::Init()
{
    m_pFrameData = new BJ_UINT8[BJ_MAX_PACKET];

    return (m_pFrameData != NULL);
}

bool CCaptureFile::Clear()
{
    delete m_pFrameData; m_pFrameData = NULL;

    if (m_hPCap)
    {
        pcap_close(m_hPCap);
        m_hPCap = NULL;
    }
    return true;
}

bool CCaptureFile::Open(const char* pFileName)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    m_hPCap = pcap_ng_open_offline(pFileName, errbuf);
    if (m_hPCap)
    {
        m_bFormatIsPCapNG = true;
    }
    else
    {
        errbuf[0] = '\0';
        m_hPCap = pcap_open_offline(pFileName, errbuf);
        if (!m_hPCap)
        {
            printf("Failed to open %s: %s\n", pFileName, errbuf);
            return false;
        }
        m_bFormatIsPCapNG = false;
    }

    if (!m_bFormatIsPCapNG)
    {
        m_datalinkType = (Frame::BJ_DATALINKTYPE)pcap_datalink(m_hPCap);
        m_CurrentFrame.SetDatalinkType(m_datalinkType);
    }
    return true;
}

bool CCaptureFile::NextFrame()
{
    if (!m_hPCap)
    {
        return false;
    }

    struct pcap_pkthdr *pPktHdr = NULL;
    bool bGotPacket = false;
    while (!bGotPacket)
    {
        const u_char *pPktData = NULL;
        const int status = pcap_next_ex(m_hPCap, &pPktHdr, &pPktData);
        if (status != 1)
        {
            if (status != PCAP_ERROR_BREAK)
            {
                const char *errstr = NULL;
                if (status == PCAP_ERROR)
                {
                    errstr = pcap_geterr(m_hPCap);
                }
                printf("Failed to read next packet with status code %d: %s\n", status, errstr ? errstr : "");
            }
            return false;
        }
        if (m_bFormatIsPCapNG)
        {
            // From the pcap_ng man page:
            //
            // Reading pcap-ng blocks
            //   To read blocks from a pcap-ng file opened by pcap_ng_fopen_offline() or
            //   pcap_ng_open_offline() simply call the traditional functions pcap_dispatch() or pcap_loop()
            //   or pcap_next() or pcap_next_ex().  The difference is that instead of getting a pointer to a
            //   packet, the function or the callback gets a buffer to a raw pcap-ng block.
            //
            //   The raw pcap-ng may be parsed manually or it may be passed to the function
            //   pcap_ng_create_with_raw_block() to create an internalized representation of the block and
            //   used with other pcap_ng accessor functions.
            pcapng_block_t block = pcap_ng_block_alloc_with_raw_block(m_hPCap, (u_char *)pPktData);
            if (block)
            {
                const bpf_u_int32 type = pcap_ng_block_get_type(block);
                switch (type)
                {
                    // Metadata blocks
                    case PCAPNG_BT_SHB:
                    case PCAPNG_BT_IDB:
                    case PCAPNG_BT_NRB:
                    case PCAPNG_BT_ISB:
                    case PCAPNG_BT_DSB:
                    case PCAPNG_BT_PIB:
                    case PCAPNG_BT_OSEV:
                        break;

                    // Packet blocks
                    case PCAPNG_BT_PB:
                    case PCAPNG_BT_SPB:
                    case PCAPNG_BT_EPB:
                    {
                        bGotPacket = true;
                        const void * const pDataPtr = pcap_ng_block_packet_get_data_ptr(block);
                        m_nCaptureLen = pcap_ng_block_packet_get_data_len(block);
                        if (m_nCaptureLen > BJ_MAX_PACKET)
                        {
                            m_nCaptureLen = BJ_MAX_PACKET;
                        }
                        memcpy(m_pFrameData, pDataPtr, m_nCaptureLen);
                        break;
                    }
                    default:
                        fprintf(stderr, "Unhandled pcap-ng block type: 0x%X\n", type);
                        break;
                }
                pcap_ng_free_block(block);
                block = NULL;
            }
        }
        else
        {
            // For traditional pcaps, a successful call to pcap_next_ex() means we got a packet header and data.
            bGotPacket = true;
            m_nCaptureLen = pPktHdr->caplen;
            if (m_nCaptureLen > BJ_MAX_PACKET)
            {
                m_nCaptureLen = BJ_MAX_PACKET;
            }
            memcpy(m_pFrameData, pPktData, m_nCaptureLen);
        }
        if (bGotPacket)
        {
            m_nWireLen = pPktHdr->len;
            m_TimeSec = pPktHdr->ts.tv_sec;
            if (m_nFirstFrameTime == 0)
            {
                m_nFirstFrameTime = m_TimeSec;
            }
        }
    }

    m_CurrentFrame.Set(m_pFrameData, m_nCaptureLen, (pPktHdr->ts.tv_sec * 1000000ll) + pPktHdr->ts.tv_usec);


    return true;
}

bool CCaptureFile::Close()
{

    return true;
}

time_t CCaptureFile::GetDeltaTime()
{
    return m_TimeSec-m_nFirstFrameTime;
}

__uint32_t CCaptureFile::GetBufferLen(BJ_UINT8* pStart)
{
    return m_nCaptureLen -  (__uint32_t) (pStart - m_pFrameData);
}





