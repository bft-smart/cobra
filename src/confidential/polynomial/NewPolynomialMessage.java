package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class NewPolynomialMessage extends PolynomialMessage {
    private PolynomialCreationContext context;

    public NewPolynomialMessage() {}

    public NewPolynomialMessage(int sender, PolynomialCreationContext context) {
        super(context.getId(), sender);
        this.context = context;
    }

    public PolynomialCreationContext getContext() {
        return context;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        context.writeExternal(out);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        context = new PolynomialCreationContext();
        context.readExternal(in);
    }
}
