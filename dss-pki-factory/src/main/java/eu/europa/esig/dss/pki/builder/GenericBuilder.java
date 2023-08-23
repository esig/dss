package eu.europa.esig.dss.pki.builder;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;

public class GenericBuilder<F> {


    private final List<Consumer<F>> instanceModifiers = new ArrayList<>();
    private final Supplier<F> instantiator;

    public GenericBuilder(Supplier<F> instantiator) {
        this.instantiator = instantiator;
    }

    public static <F> GenericBuilder<F> of(Supplier<F> instantiator) {
        return new GenericBuilder<>(instantiator);
    }

    public <U> GenericBuilder<F> with(BiConsumer<F, U> consumer, U value) {
        Consumer<F> c = instance -> consumer.accept(instance, value);
        instanceModifiers.add(c);
        return this;
    }

    public F build() {
        F value = instantiator.get();
        instanceModifiers.forEach(modifier -> modifier.accept(value));
        instanceModifiers.clear();
        return value;
    }
}