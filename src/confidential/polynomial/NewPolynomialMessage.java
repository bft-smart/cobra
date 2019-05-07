package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;

public class NewPolynomialMessage extends PolynomialMessage {
    private PolynomialContext context;

    public NewPolynomialMessage() {}

    public NewPolynomialMessage(int sender, PolynomialContext context) {
        super(context.getId(), sender);
        this.context = context;
    }

    public PolynomialContext getContext() {
        return context;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        context.writeExternal(out);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        super.readExternal(in);
        context = new PolynomialContext();
        context.readExternal(in);
    }
}
