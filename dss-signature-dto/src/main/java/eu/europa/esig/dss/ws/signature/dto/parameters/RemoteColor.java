package eu.europa.esig.dss.ws.signature.dto.parameters;

import java.io.Serializable;

@SuppressWarnings("serial")
public class RemoteColor implements Serializable {

	private Integer red;
	private Integer green;
	private Integer blue;
	private Integer alpha;

	public RemoteColor() {
	}

	public RemoteColor(int red, int green, int blue) {
		this.red = red;
		this.green = green;
		this.blue = blue;
	}

	public RemoteColor(Integer red, Integer green, Integer blue, Integer alpha) {
		this.red = red;
		this.green = green;
		this.blue = blue;
		this.alpha = alpha;
	}

	public Integer getRed() {
		return red;
	}

	public void setRed(Integer red) {
		this.red = red;
	}

	public Integer getGreen() {
		return green;
	}

	public void setGreen(Integer green) {
		this.green = green;
	}

	public Integer getBlue() {
		return blue;
	}

	public void setBlue(Integer blue) {
		this.blue = blue;
	}

	public Integer getAlpha() {
		return alpha;
	}

	public void setAlpha(Integer alpha) {
		this.alpha = alpha;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((alpha == null) ? 0 : alpha.hashCode());
		result = prime * result + ((blue == null) ? 0 : blue.hashCode());
		result = prime * result + ((green == null) ? 0 : green.hashCode());
		result = prime * result + ((red == null) ? 0 : red.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		RemoteColor other = (RemoteColor) obj;
		if (alpha == null) {
			if (other.alpha != null) {
				return false;
			}
		} else if (!alpha.equals(other.alpha)) {
			return false;
		}
		if (blue == null) {
			if (other.blue != null) {
				return false;
			}
		} else if (!blue.equals(other.blue)) {
			return false;
		}
		if (green == null) {
			if (other.green != null) {
				return false;
			}
		} else if (!green.equals(other.green)) {
			return false;
		}
		if (red == null) {
			if (other.red != null) {
				return false;
			}
		} else if (!red.equals(other.red)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "RemoteColor [red=" + red + ", green=" + green + ", blue=" + blue + ", alpha=" + alpha + "]";
	}

}
