package eu.europa.esig.dss.cms.stream.validation;

import org.junit.platform.suite.api.ExcludeTags;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectPackages("eu.europa.esig.dss.cades.validation")
@ExcludeTags("atst-v2")
class CMSStreamCAdESValidationSuiteTest {
}
