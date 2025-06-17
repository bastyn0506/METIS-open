using UnityEngine;

public class FreeCameraController : MonoBehaviour
{
    public float moveSpeed = 10f;
    public float lookSpeed = 2f;

    float yaw = 0f;
    float pitch = 0f;

    void Start()
    {
        Cursor.lockState = CursorLockMode.Locked;
    }

    void Update()
    {
        // ���_�̉�]
        yaw += lookSpeed * Input.GetAxis("Mouse X");
        pitch -= lookSpeed * Input.GetAxis("Mouse Y");
        pitch = Mathf.Clamp(pitch, -90f, 90f);
        transform.eulerAngles = new Vector3(pitch, yaw, 0f);

        // �ړ��̓���
        float horizontal = Input.GetAxis("Horizontal"); // A/D
        float vertical = Input.GetAxis("Vertical");     // W/S

        Vector3 move = transform.right * horizontal + transform.forward * vertical;

        // �㏸�E���~
        if (Input.GetKey(KeyCode.Space))
        {
            move += transform.up; // �㏸
        }
        if (Input.GetKey(KeyCode.LeftShift))
        {
            move -= transform.up; // ���~
        }

        transform.position += move * moveSpeed * Time.deltaTime;
    }
}

