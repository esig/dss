package eu.europa.esig.dss.validation.process;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class ValidationProcessUtilsTest {

    @Test
    public void getDomainNameTest() {
        assertNull(ValidationProcessUtils.getDomainName(null));
        assertEquals("", ValidationProcessUtils.getDomainName(""));
        assertEquals(" ", ValidationProcessUtils.getDomainName(" "));
        assertEquals("test", ValidationProcessUtils.getDomainName("test"));
        assertEquals(".test", ValidationProcessUtils.getDomainName(".test"));
        assertEquals("test.gov", ValidationProcessUtils.getDomainName("test.gov"));
        assertEquals(".test.gov", ValidationProcessUtils.getDomainName(".test.gov"));
        assertEquals("test.gov", ValidationProcessUtils.getDomainName("www.test.gov"));
        assertEquals("test.gov", ValidationProcessUtils.getDomainName("test.gov/subdirectory"));
        assertEquals("test.gov", ValidationProcessUtils.getDomainName("www.test.gov/subdirectory"));
        assertEquals("test.gov", ValidationProcessUtils.getDomainName("http://test.gov"));
        assertEquals("test.gov", ValidationProcessUtils.getDomainName("https://www.test.gov"));
        assertEquals("test.gov", ValidationProcessUtils.getDomainName("ftp://test.gov:80"));
        assertEquals("test.gov", ValidationProcessUtils.getDomainName("test.gov#page40"));
        assertEquals("test.gov", ValidationProcessUtils.getDomainName("test.gov/read#page40"));
        assertEquals("test.gov", ValidationProcessUtils.getDomainName("test.gov?name=robert"));
        assertEquals("test.gov", ValidationProcessUtils.getDomainName("test.gov/read?name=robert"));
    }
    
}
