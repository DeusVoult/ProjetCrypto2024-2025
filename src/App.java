public class App {
    public static void main(String[] args) throws Exception {
        if (args[3].isEmpty()) {
            System.out.println("Missing certificate name");
            return;
        }else{
        switch(args[0]){
            case "validate-cert":
                exo31 exo1 = new exo31();
                exo1.validatecert(args);
                break;
            case "validate-cert-chain":
                exo32 exo2 = new exo32();
                exo33 exo3 = new exo33();
                exo2.validatecertchain(args);
                //exo3.revokationcertchain(args);
                break;
            default:
                System.out.println("Unknown command");
                return;
            }
        }
    }
}
