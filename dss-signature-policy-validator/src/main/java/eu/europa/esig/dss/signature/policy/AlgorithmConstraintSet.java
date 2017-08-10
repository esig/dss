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