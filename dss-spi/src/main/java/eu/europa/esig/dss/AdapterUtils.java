package eu.europa.esig.dss;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class AdapterUtils {
	
	public static int[] bigIntegerListToIntArray(List<BigInteger> v) {
		int intArray[] = new int[v.size()];
		for (int i = 0; i < v.size(); i++) {
			intArray[i] = v.get(i).intValue();
		}
		return intArray;
	}

	public static List<BigInteger> intArrayToBigIntegerList(int[] v) {
		List<BigInteger> bi = new ArrayList<BigInteger>();
		for (int i : v) {
			bi.add(BigInteger.valueOf(i));
		}
		return bi;
	}

}
