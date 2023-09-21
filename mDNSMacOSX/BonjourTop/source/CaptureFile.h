//
//  CaptureFile.h
//  TestTB
//
//  Created by Terrin Eager on 9/14/12.
//
//

#ifndef __TestTB__CaptureFile__
#define __TestTB__CaptureFile__

#include <iostream>
#include <pcap/pcap.h>
#include "bjtypes.h"
#include "bjsocket.h"
#include "Frame.h"

class CCaptureFile
{
public:
    CCaptureFile();
    virtual ~CCaptureFile();
    bool Open(const char* pFileName);
    bool NextFrame();
    bool Close();

    Frame m_CurrentFrame;



    time_t GetDeltaTime();

    __uint32_t GetBufferLen(BJ_UINT8* pStart);

    __uint32_t GetWiredLength(){ return m_nWireLen;};


private:
    bool Init();
    bool Clear();

    pcap_t* m_hPCap;
    BJ_UINT8* m_pFrameData;
    __uint32_t  m_nCaptureLen;
    __uint32_t  m_nWireLen;
    time_t m_TimeSec;

    time_t m_nFirstFrameTime;

    Frame::BJ_DATALINKTYPE m_datalinkType;
    bool m_bFormatIsPCapNG;
};

#endif /* defined(__TestTB__CaptureFile__) */
