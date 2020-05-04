package eu.europa.esig.dss.pades;

public interface DSSNativeFont<F extends Object> {
	
	/**
	 * Returns a native font for the given implementation
	 * 
	 * @return Font object
	 */
	public abstract F getFont();

}
