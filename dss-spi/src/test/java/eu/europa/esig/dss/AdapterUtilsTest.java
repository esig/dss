package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class AdapterUtilsTest {
	
	private static final int FIRST_INT = 0;
	private static final int SECOND_INT = 548684654;
	private static final int THIRD_INT = 598684654;
	private static final int FOURTH_INT = 30000;
	
	@Test
	public void bigIntegerListToIntArrayTest() {
		List<BigInteger> bigIntegers = new ArrayList<BigInteger>();
		bigIntegers.add(BigInteger.valueOf(FIRST_INT));
		bigIntegers.add(BigInteger.valueOf(SECOND_INT));
		bigIntegers.add(BigInteger.valueOf(THIRD_INT));
		bigIntegers.add(BigInteger.valueOf(FOURTH_INT));
		int[] intArray = AdapterUtils.bigIntegerListToIntArray(bigIntegers);
		assertNotNull(intArray);
		assertEquals(4, intArray.length);
		assertEquals(FIRST_INT, intArray[0]);
		assertEquals(SECOND_INT, intArray[1]);
		assertEquals(THIRD_INT, intArray[2]);
		assertEquals(FOURTH_INT, intArray[3]);
	}
	
	@Test
	public void intArrayListToBigIntegerListTest() {
		int[] intArray = new int[] {FIRST_INT, SECOND_INT, THIRD_INT, FOURTH_INT};
		List<BigInteger> bigIntegers = AdapterUtils.intArrayToBigIntegerList(intArray);
		assertNotNull(bigIntegers);
		assertEquals(4, bigIntegers.size());
		assertEquals(FIRST_INT, bigIntegers.get(0).intValue());
		assertEquals(SECOND_INT, bigIntegers.get(1).intValue());
		assertEquals(THIRD_INT, bigIntegers.get(2).intValue());
		assertEquals(FOURTH_INT, bigIntegers.get(3).intValue());
	}

}
