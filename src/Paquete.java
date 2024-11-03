public class Paquete {
    public static final String ENOFICINA = "ENOFICINA";
    public static final String RECOGIDO = "RECOGIDO";
    public static final String ENCLASIFICACION = "ENCLASIFICACION";
    public static final String DESPACHADO = "DESPACHADO";
    public static final String ENENTREGA = "ENENTREGA";
    public static final String ENTREGADO = "ENTREGADO";
    public static final String DESCONOCIDO = "DESCONOCIDO";

    private String estado;

    public Paquete(String estado) {
        this.estado = estado;
    }

    public String getEstado() {
        return estado;
    }
}
