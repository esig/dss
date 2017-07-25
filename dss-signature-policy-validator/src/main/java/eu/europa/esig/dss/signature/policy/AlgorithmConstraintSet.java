package eu.europa.esig.dss.signature.policy;

import java.util.List;

public interface AlgorithmConstraintSet {

	List<AlgAndLength> getSignerAlgorithmConstraints();

	List<AlgAndLength> getEeCertAlgorithmConstraints();

	List<AlgAndLength> getCaCertAlgorithmConstraints();

	List<AlgAndLength> getAaCertAlgorithmConstraints();

	List<AlgAndLength> getTsaCertAlgorithmConstraints();

}