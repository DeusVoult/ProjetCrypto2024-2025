public class App {
    public static void main(String[] args) throws Exception {
        if (args[0].equals("validate-cert")){
        exo31 exo = new exo31();
        exo.validatecert(args);
        }
    }
}
