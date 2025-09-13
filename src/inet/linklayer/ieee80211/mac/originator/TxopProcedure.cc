//
// Copyright (C) 2016 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


#include "inet/linklayer/ieee80211/mac/originator/TxopProcedure.h"

#include "inet/linklayer/ieee80211/mac/contract/IRateSelection.h"
#include "inet/physicallayer/wireless/ieee80211/mode/Ieee80211DsssMode.h"
#include "inet/physicallayer/wireless/ieee80211/mode/Ieee80211HrDsssMode.h"
#include "inet/physicallayer/wireless/ieee80211/mode/Ieee80211HtMode.h"
#include "inet/physicallayer/wireless/ieee80211/mode/Ieee80211VhtMode.h"
#include "inet/physicallayer/wireless/ieee80211/mode/Ieee80211ErpOfdmMode.h"
#include "inet/physicallayer/wireless/ieee80211/mode/Ieee80211OfdmMode.h"

namespace inet {
namespace ieee80211 {

using namespace inet::physicallayer;

simsignal_t TxopProcedure::txopStartedSignal = cComponent::registerSignal("txopStarted");
simsignal_t TxopProcedure::txopEndedSignal = cComponent::registerSignal("txopEnded");

Define_Module(TxopProcedure);

void TxopProcedure::initialize(int stage)
{
    ModeSetListener::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        limit = par("txopLimit");
        WATCH(start);
        WATCH(protectionMechanism);
    }
}

//
// IEEE 802.11-2016 Table 9-137 "Default EDCA Parameter Set element parameter values if dot11OCBActivated is false"
//
s TxopProcedure::getTxopLimit(const IIeee80211Mode *mode, AccessCategory ac)
{
    bool isDsss = dynamic_cast<const Ieee80211DsssMode *>(mode)     || dynamic_cast<const Ieee80211HrDsssMode *>(mode);
    bool isOfdm = dynamic_cast<const Ieee80211VhtMode *>(mode)      || dynamic_cast<const Ieee80211HtMode *>(mode)  ||
                  dynamic_cast<const Ieee80211ErpOfdmMode *>(mode)  || dynamic_cast<const Ieee80211OfdmMode *>(mode);

    switch (ac) {
        case AC_BK:
        case AC_BE:
            if (isDsss) return ms(3.264);
            if (isOfdm) return ms(2.528);
            break;
        case AC_VI:
            if (isDsss) return ms(6.016);
            if (isOfdm) return ms(4.096);
            break;
        case AC_VO:
            if (isDsss) return ms(3.264);
            if (isOfdm) return ms(2.080);
            break;
        default:
            throw cRuntimeError("Unknown access category = %d", ac);
    }
    return s(0);
}


TxopProcedure::ProtectionMechanism TxopProcedure::selectProtectionMechanism(AccessCategory ac) const
{
    return ProtectionMechanism::SINGLE_PROTECTION;
}

simtime_t TxopProcedure::getStart() const
{
    return start;
}

simtime_t TxopProcedure::getLimit() const
{
    return limit;
}

void TxopProcedure::startTxop(AccessCategory ac)
{
    Enter_Method("startTxop");
    if (start != -1)
        throw cRuntimeError("Txop is already running");
    if (limit == -1) {
        auto referenceMode = modeSet->getSlowestMandatoryMode();
        EV_DETAIL << "TxopProcedure::startTxop() AC: " << ac << " | modeSet: " << modeSet->getName() << endl;
        limit = getTxopLimit(referenceMode, ac).get();
    }
    // The STA selects between single and multiple protection when it transmits the first frame of a TXOP.
    // All subsequent frames transmitted by the STA in the same TXOP use the same class of duration settings.
    protectionMechanism = selectProtectionMechanism(ac);
    start = simTime();
    emit(txopStartedSignal, this);
    EV_INFO << "Txop started: limit = " << limit << ".\n";
}

void TxopProcedure::endTxop()
{
    Enter_Method("endTxop");
    emit(txopEndedSignal, this);
    start = -1;
    protectionMechanism = ProtectionMechanism::UNDEFINED_PROTECTION;
    EV_INFO << "Txop ended.\n";
}

simtime_t TxopProcedure::getRemaining() const
{
    if (start == -1)
        throw cRuntimeError("Txop has not started yet");
    auto now = simTime();
    return now >= start + limit ? 0 : (start + limit - now);
}

simtime_t TxopProcedure::getDuration() const
{
    if (start == -1)
        throw cRuntimeError("Txop has not started yet");
    return simTime() - start;
}

// FIXME check if there is enough remaining TXOP time to send another frame
// if remainingTime < (currentDataDuration + SIFS + currentAckDuration + SIFS + optional RTS-SIFS-CTS-SIFS + nextDataDuration + SIFS + nextAckDuration)
bool TxopProcedure::isFinalFragment(const Ptr<const Ieee80211MacHeader>& header) const
{
    if (start == -1)
        throw cRuntimeError("Txop has not started yet");
    EV_DETAIL << "TXOP elapsed time: " << getDuration() * 1000 << " ms | remaining time: " << getRemaining() * 1000 << " ms" << endl;
    if (limit == 0) {
        EV_DETAIL << "TXOP: Only permitted to send one frame fragment" << endl;
        return true;
    }
    else if (!header->getMoreFragments()) {
        EV_DETAIL << "TXOP: This is the final (or whole) fragment of the current frame" << endl;
        return true;
    }
    else {
        EV_DETAIL << "TXOP: This is NOT the final fragment" << endl;
        return false;
    }
}

bool TxopProcedure::isFinalFrame(const simtime_t totalDurationNeeded, bool hasPendingFrame) const
{
    if (start == -1)
        throw cRuntimeError("TXOP has not started yet");
    
    EV_DETAIL << "TXOP elapsed time: " << getDuration() * 1000 << " ms | remaining time: " << getRemaining() * 1000 << " ms" << endl;

    if (limit == 0) {
        EV_DETAIL << "TXOP: Only permitted to send one frame" << endl;
        return true;
    }
    if (!hasPendingFrame) {
        EV_DETAIL << "TXOP: No pending frame, considered final frame" << endl;
        return true;
    }

    return getRemaining() < totalDurationNeeded;
}

// FIXME implement!
bool TxopProcedure::isTxopInitiator(const Ptr<const Ieee80211MacHeader>& header) const
{
    return false;
}

// FIXME implement!
bool TxopProcedure::isTxopTerminator(const Ptr<const Ieee80211MacHeader>& header) const
{
    return false;
}

Register_ResultFilter("txopDuration", TxopDurationFilter);

void TxopDurationFilter::receiveSignal(cResultFilter *prev, simtime_t_cref t, cObject *object, cObject *details)
{
    fire(this, t, check_and_cast<TxopProcedure *>(object)->getDuration(), details);
}

} // namespace ieee80211
} // namespace inet

