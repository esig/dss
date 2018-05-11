package eu.europa.esig.dss.client;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.client.http.DataLoader;

public class MemoryDataLoader implements DataLoader {
	private static final long serialVersionUID = -2899281917849499181L;
	
	Map<String, byte[]> dataMap = new HashMap<>();
	
	public MemoryDataLoader(Map<String, byte[]> dataMap) {
		this.dataMap.putAll(dataMap);
	}

	@Override
	public byte[] get(String url) {
		return dataMap.get(url);
	}

	@Override
	public DataAndUrl get(List<String> urlStrings) {
		for(String url : urlStrings) {
			byte[] data = get(url);
			if (data != null) {
				return new DataAndUrl(data, url);
			}
		}
		return null;
	}

	@Override
	public byte[] get(String url, boolean refresh) {
		return get(url);
	}

	@Override
	public byte[] post(String url, byte[] content) {
		return get(url);
	}

	@Override
	public void setContentType(String contentType) {
	}
}
