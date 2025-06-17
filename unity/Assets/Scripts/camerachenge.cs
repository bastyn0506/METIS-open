using UnityEngine;

public class CameraSwitcher : MonoBehaviour
{
    public Camera mainCamera;
    public Camera uiCamera;

    private bool mainActive = true;

    void Start()
    {
        SetCamera(mainCamera, true);
        SetCamera(uiCamera, false);
        UpdateCursor(); // �N�����̃J�[�\�����
    }

    void Update()
    {
        if (Input.GetKeyDown(KeyCode.C))  // �� �J�����؂�ւ��L�[
        {
            mainActive = !mainActive;
            SetCamera(mainCamera, mainActive);
            SetCamera(uiCamera, !mainActive);
            UpdateCursor(); // �؂�ւ���̃J�[�\����ԍX�V
        }
    }

    void SetCamera(Camera cam, bool enable)
    {
        cam.enabled = enable;
        AudioListener listener = cam.GetComponent<AudioListener>();
        if (listener) listener.enabled = enable;
    }

    void UpdateCursor()
    {
        if (mainActive)
        {
            Cursor.lockState = CursorLockMode.Locked; // �Œ肵�Ĕ�\��
            Cursor.visible = false;
        }
        else
        {
            Cursor.lockState = CursorLockMode.None;   // ���R�ɂ��ĕ\��
            Cursor.visible = true;
        }
    }
}


