using UnityEngine;

public class SonarScanRotator : MonoBehaviour
{
    public float rotationSpeed = 30f; // ��]���x�i�x/�b�j

    void Update()
    {
        transform.Rotate(Vector3.up, rotationSpeed * Time.deltaTime);
    }
}

