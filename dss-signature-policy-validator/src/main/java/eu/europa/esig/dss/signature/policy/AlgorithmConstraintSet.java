/*******************************************************************************
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
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy;

import java.util.List;

/** 
 * Definitions from ETSI TR 102 272 V1.1.1, Annex B, item B.9:
 * <blockquote>The signature validation policy may identify a set of signing algorithms (hashing, public key, 
 * combinations) and minimum key lengths that may be used</blockquote>
 * @see <a href="http://www.etsi.org/deliver/etsi_tr/102200_102299/102272/01.01.01_60/tr_102272v010101p.pdf">ETSI TR 102 272 V1.1.1</a>
 * @author davyd.santos
 *
 */
public interface AlgorithmConstraintSet {

	/**
	 *  Restriction to be applied by the signer in creating the signature
	 * @return
	 */
	List<AlgAndLength> getSignerAlgorithmConstraints();

	/**
	 * Restriction to be applied in end entity public key Certificates
	 * @return
	 */
	List<AlgAndLength> getEeCertAlgorithmConstraints();

	/**
	 * Restriction to be applied CA Certificates
	 * @return
	 */
	List<AlgAndLength> getCaCertAlgorithmConstraints();

	/**
	 * Restriction to be applied attribute Certificates
	 * @return
	 */
	List<AlgAndLength> getAaCertAlgorithmConstraints();

	/**
	 * Restriction to be applied by the time-stamping authority.
	 * @return
	 */
	List<AlgAndLength> getTsaCertAlgorithmConstraints();

}
