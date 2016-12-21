package eu.europa.esig.dss.asic.signature;

import java.util.List;

import eu.europa.esig.dss.DSSDocument;

public interface GetDataToSignASiCWithCAdESHelper extends GetDataToSignHelper {

	/* In CMS/CAdES, we only can sign on file */
	DSSDocument getToBeSigned();

	/* In case of parallel ASiC-S signature, we need the detached content */
	List<DSSDocument> getDetachedContents();

}
