import chainlit as cl
from chainlit.types import ThreadDict


@cl.on_chat_start
async def on_chat_start():
    print("A new chat session has started!")
    
    image = cl.Image(path="./src/cat.jpg", name="cat image", display="page")
    
    await cl.Message(
        content="Here is the cat image!",
        elements=[image],
    ).send()

@cl.step(type="tool")
async def tool():
    await cl.sleep(2)
    
    return "Response from the tool!"

@cl.on_message
async def main(message: cl.Message):
    # Your custom logic goes here...
    print(cl.chat_context.to_openai())
    
    # Call the tool
    tool_res = await tool()

    # Send a response back to the user
    await cl.Message(
        content=f"{tool_res}. Received: {message.content}",
    ).send()


@cl.on_stop
async def on_stop():
    print("The user disconnected!")


@cl.on_chat_resume
async def on_chat_resume(thread: ThreadDict):
    print("The user resumed a previous chat session!")

@cl.set_starters
async def set_starters():
    return [
        cl.Starter(
            label="Morning routine ideation",
            message="Can you help me create a personalized morning routine that would help increase my productivity throughout the day? Start by asking me about my current habits and what activities energize me in the morning.",
        ),
        cl.Starter(
            label="Explain superconductors",
            message="Explain superconductors like I'm five years old.",
            ),
        cl.Starter(
            label="Python script for daily email reports",
            message="Write a script to automate sending daily email reports in Python, and walk me through how I would set it up.",
            ),
        cl.Starter(
            label="Text inviting friend to wedding",
            message="Write a text asking a friend to be my plus-one at a wedding next month. I want to keep it super short and casual, and offer an out.",
            )
    ]