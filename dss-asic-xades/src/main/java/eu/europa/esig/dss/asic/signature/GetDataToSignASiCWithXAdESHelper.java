package eu.europa.esig.dss.asic.signature;

import java.util.List;

import eu.europa.esig.dss.DSSDocument;

public interface GetDataToSignASiCWithXAdESHelper extends GetDataToSignHelper {

	/* XAdES allows to sign more than one file */
	List<DSSDocument> getToBeSigned();

	/* For parallel signature in ASiC-S */
	DSSDocument getExistingSignature();

}
