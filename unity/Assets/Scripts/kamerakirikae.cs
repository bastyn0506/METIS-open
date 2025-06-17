using UnityEngine;

public class DisplaySwitcher : MonoBehaviour
{
    public Camera mainCamera;
    private bool usingDisplay2 = false;

    void Start()
    {
        if (Display.displays.Length > 1)
        {
            Display.displays[1].Activate(); // Display 2 ��L����
        }

        // ������Display 1��
        mainCamera.targetDisplay = 0;
    }

    void Update()
    {
        if (Input.GetKeyDown(KeyCode.Tab))
        {
            usingDisplay2 = !usingDisplay2;

            // Display 0 = �f�B�X�v���C1�ADisplay 1 = �f�B�X�v���C2
            mainCamera.targetDisplay = usingDisplay2 ? 1 : 0;
        }
    }
}


