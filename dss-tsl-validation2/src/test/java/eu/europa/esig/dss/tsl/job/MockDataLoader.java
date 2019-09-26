package eu.europa.esig.dss.tsl.job;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.spi.client.http.DataLoader;

public class MockDataLoader implements DataLoader {

	private static final long serialVersionUID = 4624853984865942793L;
	
	private Map<String, byte[]> dataMap = new HashMap<String, byte[]>();
	
	MockDataLoader(Map<String, byte[]> dataMap) {
		this.dataMap = dataMap;
	}

	@Override
	public byte[] get(String url) {
		return dataMap.get(url);
	}

	@Override
	public DataAndUrl get(List<String> urlStrings) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] get(String url, boolean refresh) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] post(String url, byte[] content) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setContentType(String contentType) {
		// TODO Auto-generated method stub
		
	}
	
}