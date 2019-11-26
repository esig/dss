package eu.europa.esig.dss.ws.timestamp.dto;

import java.io.Serializable;
import java.util.Arrays;

@SuppressWarnings("serial")
public class TimestampResponseDTO implements Serializable {
	
    private byte[] binaries;
    
    public TimestampResponseDTO() {
    }

    public byte[] getBinaries() {
        return binaries;
    }

    public void setBinaries(byte[] binaries) {
        this.binaries = binaries;
    }

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(binaries);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		TimestampResponseDTO trDTO = (TimestampResponseDTO) obj;
		if (!Arrays.equals(binaries, trDTO.binaries))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "TimestampResponseDTO [bytes=" + Arrays.toString(binaries) + "]";
	}

}
