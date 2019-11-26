package eu.europa.esig.dss.asic.common.definition;

import eu.europa.esig.dss.definition.AbstractPaths;

public class ASiCPaths extends AbstractPaths {

	public static final String ASIC_MANIFEST_PATH = fromCurrentPosition(ASiCElement.ASIC_MANIFEST);

	public static final String DATA_OBJECT_REFERENCE_PATH = fromCurrentPosition(ASiCElement.DATA_OBJECT_REFERENCE);
	
	public static final String SIG_REFERENCE_PATH = fromCurrentPosition(ASiCElement.SIG_REFERENCE);

	public static final String SIG_REFERENCE_URI_PATH = fromCurrentPosition(ASiCElement.SIG_REFERENCE, ASiCAttribute.URI);
	
}
