public class App {
    public static void main(String[] args) throws Exception {
        if (args[3].isEmpty()) {
            System.out.println("Missing certificate name");
            return;
        }else{
        switch(args[0]){
            case "validate-cert":
                exo31 exo = new exo31();
                exo.validatecert(args);
                break;
            default:
                System.out.println("Unknown command");
                return;
            }
        }
    }
}
