package eu.europa.esig.dss.util;

import static org.junit.Assert.*;

import java.util.Collections;
import java.util.Date;
import java.util.Iterator;

import org.junit.Test;

public class TimeDependentTest {

	@Test
	public void emptyCollection() {
		final TimeDependentValues<BaseTimeDependent> coll = new TimeDependentValues<BaseTimeDependent>();
		assertFalse( coll.iterator().hasNext() );
	}

	@Test
	public void oneEntryCollection() {
		final BaseTimeDependent v1In = new BaseTimeDependent( null, null );
		final TimeDependentValues<BaseTimeDependent> coll = new TimeDependentValues<BaseTimeDependent>( Collections.singleton( v1In ) );
		
		final Iterator<BaseTimeDependent> i = coll.iterator();
		assertTrue( i.hasNext() );
		final BaseTimeDependent v1Out = i.next();
		assertSame( v1In, v1Out );
		assertFalse( i.hasNext() );
		
		assertSame( v1In, coll.getLatest() );
	}

	@Test
	public void oneAddOldestWithGap() {
		final BaseTimeDependent v1In = new BaseTimeDependent( new Date( 30000 ), null );
		final MutableTimeDependentValues<BaseTimeDependent> coll = new MutableTimeDependentValues<BaseTimeDependent>( Collections.singleton( v1In ) );
		final BaseTimeDependent v2In = new BaseTimeDependent( new Date( 10000 ), new Date( 20000 ) );
		coll.addOldest( v2In );
		
		final Iterator<BaseTimeDependent> i = coll.iterator();
		assertTrue( i.hasNext() );
		final BaseTimeDependent v1Out = i.next();
		assertSame( v1In, v1Out );
		assertTrue( i.hasNext() );
		final BaseTimeDependent v2Out = i.next();
		assertSame( v2In, v2Out );
		assertFalse( i.hasNext() );

		assertSame( v1In, coll.getLatest() );
		assertNull( coll.getCurrent( new Date( 0 ) ) );
		assertNull( coll.getCurrent( new Date( 5000 ) ) );
		assertSame( v2In, coll.getCurrent( new Date( 10000 ) ) );
		assertSame( v2In, coll.getCurrent( new Date( 15000 ) ) );
		assertNull( coll.getCurrent( new Date( 20000 ) ) );
		assertNull( coll.getCurrent( new Date( 25000 ) ) );
		assertSame( v1In, coll.getCurrent( new Date( 30000 ) ) );
		assertSame( v1In, coll.getCurrent( new Date( 35000 ) ) );
		assertSame( v1In, coll.getCurrent( new Date( 40000 ) ) );
		assertSame( v1In, coll.getCurrent( new Date() ) );
		assertSame( v1In, coll.getCurrent( new Date( System.currentTimeMillis() + 5000 ) ) );
	}

	@Test
	public void oneAddOldestBackToBack() {
		final Date dx = new Date( 30000 );
		final BaseTimeDependent v1In = new BaseTimeDependent( dx, null );
		final MutableTimeDependentValues<BaseTimeDependent> coll = new MutableTimeDependentValues<BaseTimeDependent>( Collections.singleton( v1In ) );
		final BaseTimeDependent v2In = new BaseTimeDependent( new Date( 10000 ), dx );
		coll.addOldest( v2In );
		
		final Iterator<BaseTimeDependent> i = coll.iterator();
		assertTrue( i.hasNext() );
		final BaseTimeDependent v1Out = i.next();
		assertSame( v1In, v1Out );
		assertTrue( i.hasNext() );
		final BaseTimeDependent v2Out = i.next();
		assertSame( v2In, v2Out );
		assertFalse( i.hasNext() );

		assertSame( v1In, coll.getLatest() );
		assertNull( coll.getCurrent( new Date( 0 ) ) );
		assertNull( coll.getCurrent( new Date( 5000 ) ) );
		assertSame( v2In, coll.getCurrent( new Date( 10000 ) ) );
		assertSame( v2In, coll.getCurrent( new Date( 15000 ) ) );
		assertSame( v2In, coll.getCurrent( new Date( 20000 ) ) );
		assertSame( v2In, coll.getCurrent( new Date( 25000 ) ) );
		assertSame( v1In, coll.getCurrent( new Date( 30000 ) ) );
		assertSame( v1In, coll.getCurrent( new Date( 35000 ) ) );
		assertSame( v1In, coll.getCurrent( new Date( 40000 ) ) );
		assertSame( v1In, coll.getCurrent( new Date() ) );
		assertSame( v1In, coll.getCurrent( new Date( System.currentTimeMillis() + 5000 ) ) );
	}

	@Test
	public void oneAddOldestOverlap() {
		final BaseTimeDependent v1In = new BaseTimeDependent( new Date( 30000 ), null );
		final MutableTimeDependentValues<BaseTimeDependent> coll = new MutableTimeDependentValues<BaseTimeDependent>( Collections.singleton( v1In ) );
		final BaseTimeDependent v2In = new BaseTimeDependent( new Date( 10000 ), new Date( 40000 ) );
		try {
			coll.addOldest( v2In );
			fail();
		} catch ( IllegalArgumentException e ) {
			// ok
		}
	}

	@Test
	public void oneAddOldestLimited() {
		final Date dx = new Date( 30000 );
		final BaseTimeDependent v1In = new BaseTimeDependent( dx, new Date( 40000 ) );
		final MutableTimeDependentValues<BaseTimeDependent> coll = new MutableTimeDependentValues<BaseTimeDependent>( Collections.singleton( v1In ) );
		final BaseTimeDependent v2In = new BaseTimeDependent( new Date( 10000 ), dx );
		coll.addOldest( v2In );
		
		final Iterator<BaseTimeDependent> i = coll.iterator();
		assertTrue( i.hasNext() );
		final BaseTimeDependent v1Out = i.next();
		assertSame( v1In, v1Out );
		assertTrue( i.hasNext() );
		final BaseTimeDependent v2Out = i.next();
		assertSame( v2In, v2Out );
		assertFalse( i.hasNext() );

		assertSame( v1In, coll.getLatest() );
		assertNull( coll.getCurrent( new Date( 0 ) ) );
		assertNull( coll.getCurrent( new Date( 5000 ) ) );
		assertSame( v2In, coll.getCurrent( new Date( 10000 ) ) );
		assertSame( v2In, coll.getCurrent( new Date( 15000 ) ) );
		assertSame( v2In, coll.getCurrent( new Date( 20000 ) ) );
		assertSame( v2In, coll.getCurrent( new Date( 25000 ) ) );
		assertSame( v1In, coll.getCurrent( new Date( 30000 ) ) );
		assertSame( v1In, coll.getCurrent( new Date( 35000 ) ) );
		assertNull( coll.getCurrent( new Date( 40000 ) ) );
		assertNull( coll.getCurrent( new Date() ) );
		assertNull( coll.getCurrent( new Date( System.currentTimeMillis() + 5000 ) ) );
	}
}
