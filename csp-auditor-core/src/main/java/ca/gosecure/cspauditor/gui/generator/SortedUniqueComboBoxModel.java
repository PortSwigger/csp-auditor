package main.java.ca.gosecure.cspauditor.gui.generator;

public class SortedUniqueComboBoxModel extends javax.swing.DefaultComboBoxModel {

    public SortedUniqueComboBoxModel() {
        super();
    }

    @Override
    public void addElement(Object element) {
        insertElementAt(element, 0);
    }

    @Override
    public void insertElementAt(Object element, int index) {
        int size = getSize();
        for (index = 0; index < size; index++) {
            Comparable c = (Comparable) getElementAt(index);
            int comparison = c.compareTo(element);
            if (comparison == 0) return;
            if (comparison > 0) {
                break;
            }
        }
        super.insertElementAt(element, index);
    }

}
