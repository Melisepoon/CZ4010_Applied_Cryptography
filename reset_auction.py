

def clear_data(data):
    """
    Clear the contents of the used_names.txt file.
    """
    try:
        with open(data, "w") as file:
            file.write("")  # Write an empty string to clear the file
    except Exception as e:
        print(f"Error clearing file '{data}': {e}")



if __name__ == "__main__":
    #reset auction
    clear_choice = input("Do you want to reset the auction? (y/n): ").strip().lower()
    if clear_choice == "y":
        clear_data("public_key.txt")
        clear_data("used_names.txt")
        clear_data("auction_results.txt")
        clear_data("bid_messages.txt")
        print(f"Auction have been resetted.")