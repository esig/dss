/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.token.mocca;

import at.gv.egiz.smcc.CancelledException;
import at.gv.egiz.smcc.PinInfo;
import at.gv.egiz.smcc.pin.gui.PINGUI;
import eu.europa.esig.dss.token.PasswordInputCallback;

/**
 * This class provides automatically the PIN code. Only one call can be done. This protects the card against its
 * blocking.<br>
 * 1811/Do not throw a runtime exception when number of password tries exceeds 1 because it is unfriendly to the user
 * who has just entered the wrong PIN. (DUAT - AT reported the problem)<br>
 * 1809/Remove the RuntimeException throw when retries>1 (DG Justice DSS DUAT Testing)<br>
 * FIXME: These two issues need to be solved.
 *
 *
 */
class PINGUIAdapter implements PINGUI {

    private PasswordInputCallback callback;

    private int retries = 0;

    //Peter M. remove alreadyAsked 
    //private boolean alreadyAsked = false;

    public PINGUIAdapter(PasswordInputCallback callback) {
        this.callback = callback;
    }

    @Override
    public char[] providePIN(PinInfo pinSpec, int retries) throws CancelledException, InterruptedException {
        this.retries = retries;
        //Peter M. do not check if already asked. This code exists as a safety measure when 
        //unit testing, to avoid a wrong PIN being sent too many times and blocking the card.
        //In production, we need to allow the application user to enter a wrong PIN
        //TODO make a configurable switch for this.
//        if (alreadyAsked) {
//
//            throw new RuntimeException("Asked already!");
//        }
//        alreadyAsked = true;
        return callback.getPassword();
    }

    @Override
    public void enterPINDirect(PinInfo pinInfo, int retries) throws CancelledException, InterruptedException {

    }

    @Override
    public void enterPIN(PinInfo pinInfo, int retries) throws CancelledException, InterruptedException {
    }

    @Override
    public void validKeyPressed() {
    }

    @Override
    public void correctionButtonPressed() {
    }

    @Override
    public void allKeysCleared() {
    }

    public int getRetries() {
        return retries;
    }
}