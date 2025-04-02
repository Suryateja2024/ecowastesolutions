import sys
print("Python version:", sys.version)
print("Python path:", sys.path)

try:
    import razorpay
    print("Successfully imported razorpay")
except ImportError as e:
    print("Failed to import razorpay:", str(e))
    print("Error type:", type(e))
    print("Error details:", e.__dict__) 